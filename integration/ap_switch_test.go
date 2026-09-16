package integration_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jamesbraid/unifi-emu/inform"

	"goodkind.io/unifi-go/internal/configmap"
	"goodkind.io/unifi-go/internal/controller"
	"goodkind.io/unifi-go/network"
)

const liveEmulatorImage = "ghcr.io/jamesbraid/unifi-emu:0.5.5"

type liveRun struct {
	t                           *testing.T
	ctx                         context.Context
	root, dir, name, controller string
	commands                    int
	interrupted                 context.Context
	oracles                     map[network.DeviceID]liveExpectation
}

type liveModel struct {
	Model  string         `json:"model"`
	Type   string         `json:"type"`
	Ports  []inform.Port  `json:"ports"`
	Radios []inform.Radio `json:"radios"`
}

func liveFiveGHzRadio(t *testing.T, model liveModel) string {
	t.Helper()
	for _, radio := range model.Radios {
		if radio.Radio == "na" {
			return radio.Name
		}
	}
	t.Fatal("selected AP lacks a 5 GHz radio")
	return ""
}

// TestLiveAPSwitch runs actual containers; ordinary checks explicitly skip it.
func TestLiveAPSwitch(t *testing.T) {
	if os.Getenv("UNIFI_LIVE_E2E") != "1" {
		t.Skip("set UNIFI_LIVE_E2E=1 to run isolated Docker acceptance")
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "runs"), 0o700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(filepath.Join(root, "runs"), "live-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	t.Cleanup(stop)
	ctx, cancel := context.WithTimeout(signalContext, 12*time.Minute)
	defer cancel()
	r := &liveRun{t: t, ctx: ctx, root: root, dir: dir, name: filepath.Base(dir), interrupted: signalContext, oracles: make(map[network.DeviceID]liveExpectation)}
	r.controller = r.name + "-controller"
	t.Logf("private evidence: %s", dir)
	t.Cleanup(r.finish)
	r.prepare()
	models := r.models()
	r.writeJSON("models.json", models)
	r.command("docker", "network", "create", "--internal", "--ipv4=true", "--ipv6=false", r.name)
	r.command("docker", "run", "-d", "--name", r.controller, "--network", r.name,
		"--network-alias", "controller", "-v", dir+":/state", r.name+":controller",
		"serve", "--listen=:8080", "--advertise=http://controller:8080/inform",
		"--state=/state/devices.json", "--socket=/runtime/control.sock")
	r.until("controller ready", func() bool { return r.tryCLI("status") != nil })
	capture := r.name + "-capture"
	r.write("traffic.pcap", nil)
	r.command("docker", "run", "-d", "--name", capture, "--network", "container:"+r.controller,
		"--cap-add=NET_RAW", "--cap-add=NET_ADMIN", "-v", dir+":/evidence",
		"nicolaka/netshoot:v0.14", "tcpdump", "-U", "-i", "any", "-w", "/evidence/traffic.pcap", "tcp", "port", "8080")
	r.interruptCheckpoint("resources")
	r.write("adopt.json", []byte(`{"_type":"setparam","mgmt_cfg":"use_aes_gcm=true\n","system_cfg":"sshd.status=enabled\n"}`))
	var ids []string
	var emulators []string
	for index, model := range models {
		id := fmt.Sprintf("02:00:00:00:08:%02x", index+1)
		ids = append(ids, id)
		r.cli("adopt", "--mac="+id, "--file=/state/adopt.json")
		emulator := fmt.Sprintf("%s-device-%d", r.name, index)
		emulators = append(emulators, emulator)
		r.command("docker", "run", "-d", "--name", emulator, "--network", r.name, r.name+":emulator",
			"-inform", "http://controller:8080/inform", "-model", model.Model, "-mac", id,
			"-ip", fmt.Sprintf("192.0.2.%d", index+10), "-name", fmt.Sprintf("test-device-%d", index))
		r.until("adopted inventory", func() bool {
			var statuses []struct {
				MAC     string `json:"mac"`
				Version string `json:"reported_config_version"`
			}
			if json.Unmarshal(r.tryCLI("status"), &statuses) != nil {
				return false
			}
			for _, status := range statuses {
				if status.MAC == id && status.Version == "unifi-go-1" {
					return true
				}
			}
			return false
		})
	}
	r.configure(models, ids)
	r.interruptWhilePaused(emulators)
	r.resourceFlow(models, ids, emulators)
	r.write("devices-before.json", r.cli("devices"))
	r.cli("clients", "--device="+ids[0])
	for _, id := range ids[1:] {
		r.cli("ports", "--device="+id)
	}
	r.restart(models, ids, emulators)
	secondID, secondEmulator := r.addSecondAP(models[0], len(ids))
	ids = append(ids, secondID)
	emulators = append(emulators, secondEmulator)
	r.assertAmbiguousAPSelection()
	r.command("docker", "stop", "-t", "5", capture)
	r.command("mergecap", "-w", filepath.Join(r.dir, "combined.pcap"), filepath.Join(r.dir, "traffic-before-restart.pcap"), filepath.Join(r.dir, "traffic.pcap"))
	r.verifyCapture(ids, models)
	r.write("result.txt", []byte("PASS: live patched emulator adoption, typed Apply, observations, restart, encrypted capture\nNo physical forwarding, PoE power, or client association proof.\n"))
	if os.Getenv("UNIFI_LIVE_CHILD_PHASE") == "" {
		r.verifyInterruptions()
	}
}

func (r *liveRun) interruptWhilePaused(emulators []string) {
	if os.Getenv("UNIFI_LIVE_CHILD_PHASE") != "paused" {
		return
	}
	for _, name := range emulators {
		r.command("docker", "pause", name)
	}
	r.interruptCheckpoint("paused")
}

func (r *liveRun) interruptCheckpoint(phase string) {
	if os.Getenv("UNIFI_LIVE_CHILD_PHASE") != phase {
		return
	}
	r.write("interrupt-ready.json", []byte(`{"phase":"`+phase+`"}`))
	marker := os.Getenv("UNIFI_LIVE_CHILD_MARKER")
	if err := os.WriteFile(marker, []byte(r.dir), 0o600); err != nil {
		r.t.Fatal(err)
	}
	<-r.ctx.Done()
	r.t.Fatal("live interruption checkpoint canceled")
}

func (r *liveRun) verifyInterruptions() {
	executable, err := os.Executable()
	if err != nil {
		r.t.Fatal(err)
	}
	for _, phase := range []string{"resources", "paused"} {
		marker := filepath.Join(r.dir, "child-"+phase+"-run")
		output, err := os.OpenFile(filepath.Join(r.dir, "child-"+phase+".log"), os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			r.t.Fatal(err)
		}
		cmd := exec.CommandContext(r.ctx, executable, "-test.run=^TestLiveAPSwitch$", "-test.v", "-test.timeout=5m")
		cmd.Dir = filepath.Join(r.root, "integration")
		cmd.Env = append(os.Environ(), "UNIFI_LIVE_PARENT_RUN="+r.dir, "UNIFI_LIVE_CHILD_PHASE="+phase, "UNIFI_LIVE_CHILD_MARKER="+marker)
		cmd.Stdout, cmd.Stderr = output, output
		cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
		cmd.WaitDelay = time.Minute
		if err := cmd.Start(); err != nil {
			output.Close()
			r.t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		ready := false
		deadline := time.NewTimer(3 * time.Minute)
		for !ready {
			select {
			case err := <-done:
				output.Close()
				deadline.Stop()
				r.t.Fatalf("interruption child exited before checkpoint: %v", err)
			case <-deadline.C:
				_ = cmd.Process.Signal(syscall.SIGTERM)
				<-done
				output.Close()
				r.t.Fatal("interruption child checkpoint timed out")
			case <-time.After(250 * time.Millisecond):
				_, err := os.Stat(marker)
				ready = err == nil
			}
		}
		deadline.Stop()
		interrupt := os.Signal(os.Interrupt)
		if phase == "paused" {
			interrupt = syscall.SIGTERM
		}
		if err := cmd.Process.Signal(interrupt); err != nil {
			r.t.Fatal(err)
		}
		err = <-done
		output.Close()
		if err == nil || cmd.ProcessState.ExitCode() != 1 {
			r.t.Fatal("interrupted child did not exit through failed-test cleanup")
		}
		directory, err := os.ReadFile(marker)
		if err != nil {
			r.t.Fatal(err)
		}
		childDir := string(directory)
		if _, err := os.Stat(filepath.Join(childDir, "SHA256SUMS")); err != nil {
			r.t.Fatal("interrupted run lacks manifest")
		}
		pcap, err := os.Stat(filepath.Join(childDir, "traffic.pcap"))
		if err != nil || pcap.Size() < 24 {
			r.t.Fatal("interrupted capture was not finalized")
		}
		name := filepath.Base(childDir)
		for _, suffix := range []string{"-controller", "-capture", "-device-0", "-device-1", "-device-2", "-device-3"} {
			if len(bytes.TrimSpace(r.command("docker", "ps", "-a", "--filter", "name=^/"+name+suffix+"$", "--format", "{{.Names}}"))) != 0 {
				r.t.Fatal("interrupted container remains")
			}
		}
		if len(bytes.TrimSpace(r.command("docker", "network", "ls", "--filter", "name=^"+name+"$", "--format", "{{.Name}}"))) != 0 {
			r.t.Fatal("interrupted network remains")
		}
		r.writeJSON("interrupt-"+phase+".json", struct {
			Phase, Run string
			ExitCode   int
		}{phase, childDir, 1})
	}
}

func (r *liveRun) finish() {
	if r.interrupted.Err() != nil {
		r.t.Error("live run interrupted")
	}
	if r.t.Failed() {
		r.write("result.txt", []byte("FAIL: live run failed or was interrupted; partial evidence preserved\n"))
	}
	for _, suffix := range []string{"-device-0", "-device-1", "-device-2", "-device-3", "-capture", "-controller"} {
		name := r.name + suffix
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		state, err := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.State.Paused}}", name).CombinedOutput()
		cancel()
		if err != nil {
			if !bytes.Contains(bytes.ToLower(state), []byte("no such")) {
				r.t.Errorf("inspect isolated cleanup target failed: %v", err)
			}
			continue
		}
		if strings.TrimSpace(string(state)) == "true" {
			r.cleanup("unpause", name)
		}
		r.cleanup("stop", "-t", "5", name)
		r.summarizeLogs(name)
		r.cleanup("rm", name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	output, err := exec.CommandContext(ctx, "docker", "network", "inspect", r.name).CombinedOutput()
	cancel()
	if err == nil {
		r.cleanup("network", "rm", r.name)
	} else if !bytes.Contains(output, []byte("not found")) {
		r.t.Errorf("inspect isolated network failed: %v", err)
	}
	r.manifest()
}

func (r *liveRun) prepare() {
	if parent := os.Getenv("UNIFI_LIVE_PARENT_RUN"); parent != "" {
		prefix := filepath.Base(parent)
		r.command("docker", "tag", prefix+":controller", r.name+":controller")
		r.command("docker", "tag", prefix+":emulator", r.name+":emulator")
		binary, err := os.ReadFile(filepath.Join(parent, "live-test"))
		if err != nil {
			r.t.Fatal(err)
		}
		r.write("live-test", binary)
		return
	}
	r.command("docker", "pull", liveEmulatorImage)
	r.command("docker", "pull", "nicolaka/netshoot:v0.14")
	r.command("docker", "build", "-t", r.name+":controller", r.root)
	cmdTest := exec.CommandContext(r.ctx, "go", "test", "-c", "-o", filepath.Join(r.dir, "live-test"), "./integration")
	cmdTest.Dir = r.root
	cmdTest.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	r.execute(cmdTest)
	module := strings.TrimSpace(string(r.command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/jamesbraid/unifi-emu")))
	source := filepath.Join(r.dir, "emulator-source")
	if err := os.CopyFS(source, os.DirFS(module)); err != nil {
		r.t.Fatal(err)
	}
	for _, name := range []string{"unifi-emu-port-poe.patch", "unifi-emu-system-config.patch"} {
		patch, err := os.ReadFile(filepath.Join(r.root, "poc", "patches", name))
		if err != nil {
			r.t.Fatal(err)
		}
		r.write(name, patch)
		r.command("patch", "-d", source, "-p1", "-i", filepath.Join(r.dir, name))
	}
	// Explicit synthetic family evidence disambiguates the emulator's AP port table.
	r.write("unifi-emu-family.patch", []byte("--- a/inform/session.go\n+++ b/inform/session.go\n@@ -64,3 +64,4 @@\n \tm := map[string]any{\n \t\t\"mac\":            s.desc.MAC,\n+\t\t\"type\":           s.desc.Type,\n \t\t\"serial\":         s.desc.Serial,\n"))
	r.command("patch", "-d", source, "-p1", "-i", filepath.Join(r.dir, "unifi-emu-family.patch"))
	cmd := exec.CommandContext(r.ctx, "go", "build", "-trimpath", "-o", filepath.Join(r.dir, "unifi-emu"), "./cmd/unifi-emu")
	cmd.Dir = source
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	r.execute(cmd)
	r.write("Emulator.Dockerfile", []byte("FROM "+liveEmulatorImage+"\nCOPY unifi-emu /unifi-emu\nENTRYPOINT [\"/unifi-emu\"]\n"))
	r.command("docker", "build", "-f", filepath.Join(r.dir, "Emulator.Dockerfile"), "-t", r.name+":emulator", r.dir)
	for index, image := range []string{liveEmulatorImage, r.name + ":emulator", r.name + ":controller", "nicolaka/netshoot:v0.14"} {
		r.write(fmt.Sprintf("image-%d.json", index), r.command("docker", "image", "inspect", "--format", `{"id":{{json .Id}},"digests":{{json .RepoDigests}}}`, image))
	}
	r.write("module.json", r.command("go", "mod", "download", "-json", "github.com/jamesbraid/unifi-emu@v0.5.5"))
}

func (r *liveRun) models() []liveModel {
	if parent := os.Getenv("UNIFI_LIVE_PARENT_RUN"); parent != "" {
		data, err := os.ReadFile(filepath.Join(parent, "models.json"))
		if err != nil {
			r.t.Fatal(err)
		}
		var models []liveModel
		if err := json.Unmarshal(data, &models); err != nil {
			r.t.Fatal(err)
		}
		return models
	}
	data, err := os.ReadFile(filepath.Join(r.dir, "emulator-source", "model_profiles.json"))
	if err != nil {
		r.t.Fatal(err)
	}
	var catalog struct {
		Models []liveModel `json:"models"`
	}
	if err := json.Unmarshal(data, &catalog); err != nil {
		r.t.Fatal(err)
	}
	var ap *liveModel
	var switches []liveModel
	for _, model := range catalog.Models {
		if model.Type == "uap" && len(model.Radios) == 2 && ap == nil {
			bands := map[string]bool{}
			for _, radio := range model.Radios {
				bands[radio.Radio] = true
			}
			if bands["ng"] && bands["na"] {
				copyModel := model
				ap = &copyModel
			}
		}
		if model.Type != "usw" || len(model.Ports) < 2 {
			continue
		}
		if model.Ports[0].PortIdx != 1 || model.Ports[0].PoECaps == 0 {
			continue
		}
		if len(switches) == 0 || (len(switches) == 1 && len(model.Ports) != len(switches[0].Ports)) {
			switches = append(switches, model)
		}
	}
	if ap == nil || len(switches) != 2 {
		r.t.Fatal("catalog lacks required AP and distinct PoE switch inventories")
	}
	return append([]liveModel{*ap}, switches...)
}

func (r *liveRun) configure(models []liveModel, ids []string) {
	for index := range models {
		family, fixture := "ap", "operation-05-reply.json"
		if index > 0 {
			family, fixture = "switch", "operation-08-reply.json"
		}
		param := compilerFixture(r.t, family, fixture)
		param.Management["operator.unmodeled"] = "retain-management"
		param.System["operator.unmodeled"] = "retain-system"
		if index == 0 {
			for _, radio := range models[index].Radios {
				old := "wifi-na"
				if radio.Radio == "ng" {
					old = "wifi-ng"
				}
				for key, value := range param.System {
					if value == old {
						param.System[key] = radio.Name
					}
				}
			}
			param.System["radio.1.channel"] = "44"
			param.System["radio.2.ieee_mode"] = "11nght20"
			param.System["radio.1.txpower"], param.System["radio.2.txpower"] = "12", "10"
			// The added records create synthetic legacy policy without changing the captured dual-radio WLAN.
			for key, value := range param.System.Clone() {
				for _, pair := range [][2]string{{"wireless.2.", "wireless.3."}, {"aaa.2.", "aaa.3."}, {"netconf.4.", "netconf.7."}} {
					if strings.HasPrefix(key, pair[0]) {
						param.System[pair[1]+strings.TrimPrefix(key, pair[0])] = value
					}
				}
			}
			param.System["wireless.3.ssid"], param.System["aaa.3.ssid"] = "synthetic-legacy", "synthetic-legacy"
			param.System["wireless.3.devname"], param.System["aaa.3.devname"], param.System["netconf.7.devname"] = "ath2", "ath2", "ath2"
			param.System["bridge.2.port.4.devname"] = "ath2"
			param.System["aaa.3.bss_transition"] = "disabled"
		} else {
			// Captured switch replies omit these required synthetic port identity records.
			for port := 2; port <= 5; port++ {
				prefix := fmt.Sprintf("switch.port.%d.", port)
				param.System[prefix+"status"] = "enabled"
				param.System[prefix+"pvid"] = "1"
			}
		}
		management, err := param.Management.Encode()
		if err != nil {
			r.t.Fatal(err)
		}
		system, err := param.System.Encode()
		if err != nil {
			r.t.Fatal(err)
		}
		baseline := network.BaselineImport{Config: network.Config{Version: "unifi-go-1", Management: management, System: system}}
		if index == 0 {
			radioIDs := make([]network.RadioID, 0, len(models[index].Radios))
			radios := make([]network.RadioConfig, 0, len(models[index].Radios))
			var legacyRadio network.RadioID
			for _, radio := range models[index].Radios {
				band := network.Band5GHz
				if radio.Radio == "ng" {
					band = network.Band2GHz
					legacyRadio = network.RadioID(radio.Name)
				}
				radioIDs = append(radioIDs, network.RadioID(radio.Name))
				radios = append(radios, network.RadioConfig{ID: network.RadioID(radio.Name), Band: band})
			}
			baseline.AP = &network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{
				{Name: "fixture-wifi", RadioIDs: network.Supplied(radioIDs)},
				{Name: "synthetic-legacy", RadioIDs: network.Supplied([]network.RadioID{legacyRadio})},
			}), Radios: network.Supplied(radios)}
		} else {
			baseline.Switch = &network.SwitchConfig{Ports: network.Supplied([]network.SwitchPortConfig{{Index: 2}, {Index: 3}, {Index: 4}, {Index: 5}})}
		}
		r.writeJSON(fmt.Sprintf("baseline-%d.json", index), baseline)
	}
	r.loadOracleBaselines(ids)
	r.socketOperations("initial", models, ids)
}

func (r *liveRun) resourceFlow(models []liveModel, ids, emulators []string) {
	const sourceName = "fixture-wifi"
	const destinationName = "resource-copy"
	apID := ids[0]
	beforeAdd := r.oracle(apID)
	r.write("resource-name", []byte(destinationName+"\n"))
	r.write("resource-source", []byte(sourceName+"\n"))
	password := make([]byte, 24)
	if _, err := rand.Read(password); err != nil {
		r.t.Fatal(err)
	}
	r.write("resource-password", []byte(hex.EncodeToString(password)))
	r.command("docker", "pause", emulators[0])
	added := decodeLiveQueuedVersion(r.t, r.cli("wifi", "add", "--name-file=/state/resource-name", "--password-file=/state/resource-password", "--copy-from-file=/state/resource-source"))
	r.oracleAddWiFi(apID, models[0], sourceName, destinationName, hex.EncodeToString(password))
	afterAdd := r.recordOracle("resource-add", apID, added)
	assertLiveWiFiCopy(r.t, beforeAdd.System, afterAdd.System, sourceName, destinationName)
	r.writeJSON("resource-set.json", network.WiFiNetwork{Name: destinationName, BSSTransition: network.Supplied(network.BSSTransitionDisabled)})
	stateBeforePending := r.readState()
	output, err := r.cliResult("wifi", "set", "--current-name="+destinationName, "--file=/state/resource-set.json")
	if err == nil || !bytes.Contains(output, []byte(string(network.ConfigurationPending))) {
		r.t.Fatal("second resource mutation was not rejected while configuration was pending")
	}
	if !bytes.Equal(stateBeforePending, r.readState()) || r.pending(apID) != 1 {
		r.t.Fatal("pending resource rejection changed state or queue")
	}
	r.command("docker", "unpause", emulators[0])
	r.waitVersion(apID, added)

	setVersion := decodeLiveQueuedVersion(r.t, r.cli("wifi", "set", "--device="+apID, "--current-name="+destinationName, "--file=/state/resource-set.json"))
	r.oracleSetBSS(apID, destinationName, string(network.BSSTransitionDisabled))
	afterSet := r.recordOracle("resource-wifi-set", apID, setVersion)
	assertLiveBSSPolicy(r.t, afterSet.System, sourceName, destinationName, "synthetic-legacy")
	r.waitVersion(apID, setVersion)

	var fiveGHzRadio network.RadioID
	for _, radio := range models[0].Radios {
		if radio.Radio == "na" {
			fiveGHzRadio = network.RadioID(radio.Name)
		}
	}
	if fiveGHzRadio == "" {
		r.t.Fatal("selected AP lacks a 5 GHz radio")
	}
	r.writeJSON("resource-radio.json", network.RadioConfig{ID: fiveGHzRadio, Channel: network.Supplied(uint16(157))})
	radioVersion := decodeLiveQueuedVersion(r.t, r.cli("radio", "set", "--device="+apID, "--file=/state/resource-radio.json"))
	r.oracleSetRadio(apID, string(fiveGHzRadio), 157)
	r.recordOracle("resource-radio-set", apID, radioVersion)
	r.waitVersion(apID, radioVersion)

	r.writeJSON("resource-port.json", network.SwitchPortConfig{Index: 3, Enabled: network.Supplied(false)})
	portVersion := decodeLiveQueuedVersion(r.t, r.cli("port", "set", "--device="+ids[1], "--file=/state/resource-port.json"))
	r.oracleSetPort(ids[1], 3, false)
	r.recordOracle("resource-port-set", ids[1], portVersion)
	r.waitVersion(ids[1], portVersion)

	r.writeJSON("synthetic-drift.json", network.Command{Name: "synthetic-set-report-version", Parameters: map[string]json.RawMessage{
		"cfgversion": json.RawMessage(`"synthetic-drift"`),
	}})
	r.cli("command", "--device="+apID, "--file=/state/synthetic-drift.json")
	r.waitVersion(apID, "synthetic-drift")
	stateBeforeDrift := r.readState()
	r.writeJSON("resource-drift-radio.json", network.RadioConfig{ID: fiveGHzRadio, Channel: network.Supplied(uint16(44))})
	output, err = r.cliResult("radio", "set", "--device="+apID, "--file=/state/resource-drift-radio.json")
	if err == nil || !bytes.Contains(output, []byte(string(network.ConfigurationDrift))) {
		r.t.Fatal("resource mutation was not rejected after reported drift")
	}
	if !bytes.Equal(stateBeforeDrift, r.readState()) || r.pending(apID) != 0 {
		r.t.Fatal("drift rejection changed state or queue")
	}
	current := r.persistedDevice(apID)
	if current.DesiredAP == nil {
		r.t.Fatal("persisted AP projection is unavailable for reconciliation")
	}
	r.writeJSON("resource-reconcile-ap.json", current.DesiredAP)
	reconciled := decodeLiveQueuedVersion(r.t, r.cli("apply", "ap", "--device="+apID, "--file=/state/resource-reconcile-ap.json"))
	if reconciled != radioVersion {
		r.t.Fatal("full reconciliation changed unchanged desired policy")
	}
	r.waitVersion(apID, reconciled)
}

func decodeLiveQueuedVersion(t *testing.T, body []byte) network.ConfigVersion {
	t.Helper()
	var queued struct {
		Version network.ConfigVersion `json:"version"`
	}
	if err := json.Unmarshal(body, &queued); err != nil || queued.Version == "" {
		t.Fatal("resource command omitted a queued version")
	}
	return queued.Version
}

func (r *liveRun) readState() []byte {
	body, err := os.ReadFile(filepath.Join(r.dir, "devices.json"))
	if err != nil {
		r.t.Fatal(err)
	}
	return body
}

func (r *liveRun) persistedDevice(id string) controller.Device {
	var devices []controller.Device
	if err := json.Unmarshal(r.readState(), &devices); err != nil {
		r.t.Fatal("invalid persisted controller state")
	}
	for _, device := range devices {
		if device.MAC == id {
			return device
		}
	}
	r.t.Fatal("persisted device unavailable")
	return controller.Device{}
}

func (r *liveRun) loadOracleBaselines(ids []string) {
	for index, id := range ids {
		r.loadOracleBaseline(index, id)
	}
}

func (r *liveRun) loadOracleBaseline(index int, id string) {
	body, err := os.ReadFile(filepath.Join(r.dir, fmt.Sprintf("baseline-%d.json", index)))
	if err != nil {
		r.t.Fatal(err)
	}
	var baseline network.BaselineImport
	if err := json.Unmarshal(body, &baseline); err != nil {
		r.t.Fatal("invalid oracle baseline")
	}
	management, err := configmap.Parse(baseline.Config.Management)
	if err != nil {
		r.t.Fatal(err)
	}
	system, err := configmap.Parse(baseline.Config.System)
	if err != nil {
		r.t.Fatal(err)
	}
	deviceID := network.DeviceID(id)
	r.oracles[deviceID] = liveExpectation{ID: deviceID, Management: management, System: system}
}

func (r *liveRun) oracle(id string) liveExpectation {
	expected, exists := r.oracles[network.DeviceID(id)]
	if !exists {
		r.t.Fatal("independent baseline oracle unavailable")
	}
	expected.Management = expected.Management.Clone()
	expected.System = expected.System.Clone()
	return expected
}

func (r *liveRun) saveOracle(expected liveExpectation) {
	r.oracles[expected.ID] = liveExpectation{
		ID: expected.ID, Version: expected.Version,
		Management: expected.Management.Clone(), System: expected.System.Clone(),
	}
}

func (r *liveRun) recordOracle(label, id string, version network.ConfigVersion) liveExpectation {
	expected := r.oracle(id)
	expected.Version = version
	r.saveOracle(expected)
	r.writeJSON("expected-"+label+".json", expected)
	return expected
}

func (r *liveRun) oracleSetBSS(id, name, value string) {
	expected := r.oracle(id)
	count := 0
	for _, prefix := range oracleRecordPrefixes(expected.System, "aaa.") {
		if expected.System[prefix+"ssid"] == name {
			expected.System[prefix+"bss_transition"] = value
			count++
		}
	}
	if count == 0 {
		r.t.Fatal("oracle WiFi authentication record unavailable")
	}
	r.saveOracle(expected)
}

func (r *liveRun) oracleSetRadio(id, radioID string, channel uint16) {
	expected := r.oracle(id)
	prefix := oracleMatchRecord(r.t, expected.System, "radio.", "phyname", radioID)
	expected.System[prefix+"channel"] = strconv.Itoa(int(channel))
	r.saveOracle(expected)
}

func (r *liveRun) oracleSetPort(id string, index uint16, enabled bool) {
	expected := r.oracle(id)
	status := "disabled"
	if enabled {
		status = "enabled"
	}
	expected.System[fmt.Sprintf("switch.port.%d.status", index)] = status
	r.saveOracle(expected)
}

func (r *liveRun) oracleAddWiFi(id string, model liveModel, sourceName, destinationName, password string) {
	expected := r.oracle(id)
	radios := slices.Clone(model.Radios)
	slices.SortFunc(radios, func(left, right inform.Radio) int { return strings.Compare(left.Name, right.Name) })
	for _, radio := range radios {
		sourceWireless := ""
		for _, prefix := range oracleRecordPrefixes(expected.System, "wireless.") {
			if expected.System[prefix+"ssid"] == sourceName && expected.System[prefix+"parent"] == radio.Name {
				if sourceWireless != "" {
					r.t.Fatal("oracle source WiFi is ambiguous")
				}
				sourceWireless = prefix
			}
		}
		if sourceWireless == "" {
			r.t.Fatal("oracle source WiFi is unavailable")
		}
		oldDevice := expected.System[sourceWireless+"devname"]
		sourceAAA := oracleMatchRecord(r.t, expected.System, "aaa.", "devname", oldDevice)
		wireless := oracleNextRecord(expected.System, "wireless.")
		aaa := oracleNextRecord(expected.System, "aaa.")
		deviceName := oracleAvailableInterface(expected.System, radio.Name)
		references := map[string]string{oldDevice: deviceName, radio.Name: radio.Name}
		oracleCopyRecord(expected.System, sourceWireless, wireless, references)
		oracleCopyRecord(expected.System, sourceAAA, aaa, references)

		if netconf := oracleOptionalMatchRecord(r.t, expected.System, "netconf.", "devname", oldDevice); netconf != "" {
			oracleCopyRecord(expected.System, netconf, oracleNextRecord(expected.System, "netconf."), references)
		}
		bridgeMember := oracleBridgeMember(r.t, expected.System, oldDevice)
		if bridgeMember != "" {
			head, _, _ := strings.Cut(bridgeMember, "port.")
			oracleCopyRecord(expected.System, bridgeMember, oracleNextRecord(expected.System, head+"port."), references)
		}
		for _, filter := range oracleRecordPrefixes(expected.System, "ebtables.") {
			if !oracleCommandReferences(expected.System[filter+"cmd"], oldDevice) {
				continue
			}
			target := oracleNextRecord(expected.System, "ebtables.")
			oracleCopyRecord(expected.System, filter, target, references)
			expected.System[target+"cmd"] = strings.ReplaceAll(expected.System[target+"cmd"], oldDevice, deviceName)
		}

		expected.System[wireless+"ssid"], expected.System[aaa+"ssid"] = destinationName, destinationName
		expected.System[wireless+"devname"], expected.System[aaa+"devname"] = deviceName, deviceName
		expected.System[wireless+"parent"], expected.System[aaa+"wpa.psk"] = radio.Name, password
		radioPrefix := oracleMatchRecord(r.t, expected.System, "radio.", "phyname", radio.Name)
		virtual := oracleNextRecord(expected.System, radioPrefix+"virtual.")
		expected.System[virtual+"devname"], expected.System[virtual+"mode"], expected.System[virtual+"status"] = deviceName, "master", "enabled"
	}
	r.saveOracle(expected)
}

func oracleRecordPrefixes(values configmap.Values, namespace string) []string {
	var prefixes []string
	for key := range values {
		suffix, found := strings.CutPrefix(key, namespace)
		if !found {
			continue
		}
		number, _, found := strings.Cut(suffix, ".")
		if !found {
			continue
		}
		index, err := strconv.Atoi(number)
		if err == nil && index > 0 {
			prefixes = append(prefixes, namespace+number+".")
		}
	}
	slices.Sort(prefixes)
	return slices.Compact(prefixes)
}

func oracleNextRecord(values configmap.Values, namespace string) string {
	prefixes := oracleRecordPrefixes(values, namespace)
	for index := 1; ; index++ {
		candidate := fmt.Sprintf("%s%d.", namespace, index)
		if !slices.Contains(prefixes, candidate) {
			return candidate
		}
	}
}

func oracleCopyRecord(values configmap.Values, source, destination string, references map[string]string) {
	before := values.Clone()
	for key, value := range before {
		suffix, found := strings.CutPrefix(key, source)
		if !found {
			continue
		}
		if suffix == "devname" || suffix == "parent" || suffix == "ssid" || suffix == "br.devname" {
			if replacement, exists := references[value]; exists {
				value = replacement
			}
		}
		values[destination+suffix] = value
	}
}

func oracleOptionalMatchRecord(t *testing.T, values configmap.Values, namespace, field, value string) string {
	t.Helper()
	match := ""
	for _, prefix := range oracleRecordPrefixes(values, namespace) {
		if values[prefix+field] != value {
			continue
		}
		if match != "" {
			t.Fatal("oracle record is ambiguous")
		}
		match = prefix
	}
	return match
}

func oracleMatchRecord(t *testing.T, values configmap.Values, namespace, field, value string) string {
	t.Helper()
	match := oracleOptionalMatchRecord(t, values, namespace, field, value)
	if match == "" {
		t.Fatal("oracle record is unavailable")
	}
	return match
}

func oracleBridgeMember(t *testing.T, values configmap.Values, deviceName string) string {
	t.Helper()
	match := ""
	for _, bridge := range oracleRecordPrefixes(values, "bridge.") {
		for _, member := range oracleRecordPrefixes(values, bridge+"port.") {
			if values[member+"devname"] != deviceName {
				continue
			}
			if match != "" {
				t.Fatal("oracle bridge member is ambiguous")
			}
			match = member
		}
	}
	return match
}

func oracleAvailableInterface(values configmap.Values, physical string) string {
	for index := 0; ; index++ {
		candidate := fmt.Sprintf("ath%d", index)
		suffix := strings.TrimPrefix(physical, "wifi")
		if suffix != physical && suffix != "" {
			if _, err := strconv.ParseUint(suffix, 10, 32); err == nil {
				candidate = fmt.Sprintf("%sap%d", physical, index)
			}
		}
		used := false
		for key, value := range values {
			if strings.HasSuffix(key, ".devname") && value == candidate {
				used = true
				break
			}
		}
		if !used {
			return candidate
		}
	}
}

func oracleCommandReferences(command, deviceName string) bool {
	return slices.Contains(strings.Fields(command), deviceName)
}

func (r *liveRun) waitVersion(id string, version network.ConfigVersion) {
	r.until("reported configuration version", func() bool {
		return r.snapshot(id).ReportedConfigVersion == version
	})
}

func (r *liveRun) pending(id string) int {
	return r.status(id).Pending
}

func (r *liveRun) status(id string) controller.Status {
	var statuses []controller.Status
	if err := json.Unmarshal(r.cli("status"), &statuses); err != nil {
		r.t.Fatal("invalid status response")
	}
	for _, status := range statuses {
		if status.MAC == id {
			return status
		}
	}
	r.t.Fatal("device status unavailable")
	return controller.Status{}
}

func (r *liveRun) socketOperations(phase string, models []liveModel, ids []string) {
	if err := os.Chmod(filepath.Join(r.dir, "live-test"), 0o700); err != nil {
		r.t.Fatal(err)
	}
	r.command("docker", "exec", "-e", "UNIFI_LIVE_SOCKET_PHASE="+phase, r.controller,
		"/state/live-test", "-test.run=^TestLiveSocketOperations$", "-test.v", "-test.timeout=4m")
	for index, id := range ids {
		var applied struct {
			ID      network.DeviceID
			Version network.ConfigVersion
		}
		body, err := os.ReadFile(filepath.Join(r.dir, fmt.Sprintf("applied-%s-%d.json", phase, index)))
		if err != nil || json.Unmarshal(body, &applied) != nil || applied.ID != network.DeviceID(id) || applied.Version == "" {
			r.t.Fatal("live applied result unavailable")
		}
		if phase == "initial" {
			if models[index].Type == "uap" {
				r.oracleSetBSS(id, "fixture-wifi", string(network.BSSTransitionEnabled))
				r.oracleSetBSS(id, "synthetic-legacy", string(network.BSSTransitionDisabled))
			} else {
				r.oracleSetPort(id, 2, false)
			}
		} else if models[index].Type == "uap" {
			r.oracleSetRadio(id, liveFiveGHzRadio(r.t, models[index]), 44)
		} else {
			r.oracleSetPort(id, 4, false)
		}
		r.recordOracle(fmt.Sprintf("%s-%d", phase, index), id, applied.Version)
	}
}

// TestLiveSocketOperations runs the public client inside the isolated controller container.
func TestLiveSocketOperations(t *testing.T) {
	phase := os.Getenv("UNIFI_LIVE_SOCKET_PHASE")
	if phase == "" {
		t.Skip("isolated container helper")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	client := network.Dial("/runtime/control.sock")
	devices, err := client.Devices(ctx)
	if err != nil {
		t.Fatal("socket inventory failed")
	}
	index := 0
	for _, device := range devices {
		if device.LastInform.IsZero() {
			continue
		}
		var baseline network.BaselineImport
		data, err := os.ReadFile(fmt.Sprintf("/state/baseline-%d.json", index))
		if err != nil || json.Unmarshal(data, &baseline) != nil {
			t.Fatal("baseline unavailable")
		}
		if phase == "initial" {
			if err := client.ImportBaseline(ctx, device.ID, baseline); err != nil {
				t.Fatal("baseline import failed", err)
			}
		}
		before, err := os.ReadFile("/state/devices.json")
		if err != nil {
			t.Fatal(err)
		}
		apRequest := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{
			{Name: "fixture-wifi", BSSTransition: network.Supplied(network.BSSTransitionEnabled)},
			{Name: "synthetic-legacy", BSSTransition: network.Supplied(network.BSSTransitionDisabled)},
		})}
		switchRequest := network.SwitchConfig{Ports: network.Supplied([]network.SwitchPortConfig{
			{Index: 2, Enabled: network.Supplied(false)}, {Index: 3}, {Index: 4}, {Index: 5},
		})}
		if phase == "restart" {
			persisted := liveDeviceFromState(t, "/state/devices.json", device.ID)
			if device.Family == network.FamilyAP && persisted.DesiredAP != nil {
				apRequest = persisted.DesiredAP.Clone()
				for radioIndex := range apRequest.Radios.Value {
					if apRequest.Radios.Value[radioIndex].Band == network.Band5GHz {
						apRequest.Radios.Value[radioIndex].Channel = network.Supplied(uint16(44))
					}
				}
			}
			if device.Family == network.FamilySwitch && persisted.DesiredSwitch != nil {
				switchRequest = persisted.DesiredSwitch.Clone()
				for portIndex := range switchRequest.Ports.Value {
					if switchRequest.Ports.Value[portIndex].Index == 4 {
						switchRequest.Ports.Value[portIndex].Enabled = network.Supplied(false)
					}
				}
			}
		}
		var preview network.ConfigPreview
		if device.Family == network.FamilyAP {
			preview, err = client.PreviewAP(ctx, device.ID, apRequest)
		} else {
			preview, err = client.PreviewSwitch(ctx, device.ID, switchRequest)
		}
		if err != nil {
			t.Fatal("live preview failed", err)
		}
		previewCompleted := time.Now()
		after, err := os.ReadFile("/state/devices.json")
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("preview changed state bytes")
		}
		fresh := previewCompleted
		var previewInform time.Time
		for {
			observed, err := client.Device(ctx, device.ID)
			if err != nil {
				t.Fatal("preview observation failed")
			}
			if observed.LastInform.After(fresh) {
				if observed.ReportedConfigVersion != device.ReportedConfigVersion {
					t.Fatal("preview delivered configuration")
				}
				previewInform = observed.LastInform
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("preview fresh inform timeout")
			case <-time.After(time.Second):
			}
		}
		if !previewInform.After(previewCompleted) {
			t.Fatal("preview accepted an inform received before preview completed")
		}
		if err := os.WriteFile(fmt.Sprintf("/state/preview-%s-%d.json", phase, index), mustLiveJSON(t, struct {
			ID                 network.DeviceID
			Start, Inform, End time.Time
		}{device.ID, fresh, previewInform, time.Now()}), 0o600); err != nil {
			t.Fatal(err)
		}
		var version network.ConfigVersion
		if device.Family == network.FamilyAP {
			version, err = client.ApplyAPPreview(ctx, device.ID, apRequest, preview.Token)
		} else {
			version, err = client.ApplySwitchPreview(ctx, device.ID, switchRequest, preview.Token)
		}
		if err != nil {
			t.Fatal("live token apply failed", err)
		}
		for {
			observed, err := client.Device(ctx, device.ID)
			if err != nil {
				t.Fatal("apply observation failed")
			}
			if observed.ReportedConfigVersion == version {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("apply version timeout")
			case <-time.After(time.Second):
			}
		}
		if err := os.WriteFile(fmt.Sprintf("/state/applied-%s-%d.json", phase, index), mustLiveJSON(t, struct {
			ID      network.DeviceID
			Version network.ConfigVersion
		}{device.ID, version}), 0o600); err != nil {
			t.Fatal(err)
		}
		index++
	}
	if index != 3 {
		t.Fatal("live adopted inventory does not contain three devices")
	}
}

type liveExpectation struct {
	ID                 network.DeviceID
	Version            network.ConfigVersion
	Management, System configmap.Values
}

func liveDeviceFromState(t *testing.T, path string, id network.DeviceID) controller.Device {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var devices []controller.Device
	if err := json.Unmarshal(body, &devices); err != nil {
		t.Fatal("invalid persisted controller state")
	}
	for _, device := range devices {
		if network.DeviceID(device.MAC) == id {
			return device
		}
	}
	t.Fatal("persisted device unavailable")
	return controller.Device{}
}

func mustLiveJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (r *liveRun) restart(models []liveModel, ids, emulators []string) {
	for _, name := range emulators {
		r.command("docker", "pause", name)
	}
	apID := ids[0]
	reportedBeforeRestart := r.snapshot(apID).ReportedConfigVersion
	pendingRadioID := liveFiveGHzRadio(r.t, models[0])
	r.writeJSON("restart-pending-radio.json", network.RadioConfig{ID: network.RadioID(pendingRadioID), Channel: network.Supplied(uint16(44))})
	pendingVersion := decodeLiveQueuedVersion(r.t, r.cli("radio", "set", "--device="+apID, "--file=/state/restart-pending-radio.json"))
	r.oracleSetRadio(apID, pendingRadioID, 44)
	var pendingStatus controller.Status
	r.until("typed configuration pending before restart", func() bool {
		pendingStatus = r.status(apID)
		return pendingStatus.Pending == 1 && pendingStatus.DesiredConfigVersion == pendingVersion && pendingStatus.ReportedConfigVersion == reportedBeforeRestart
	})
	r.writeJSON("restart-pending-status.json", pendingStatus)
	r.write("pending.json", []byte(`{"_type":"cmd","cmd":"must-not-replay"}`))
	for _, id := range ids {
		r.cli("send", "--mac="+id, "--file=/state/pending.json")
	}
	before, err := os.ReadFile(filepath.Join(r.dir, "devices.json"))
	if err != nil {
		r.t.Fatal(err)
	}
	r.write("state-before-restart.json", before)
	// Docker replaces the controller network namespace on restart; reattach capture.
	r.command("docker", "stop", "-t", "5", r.name+"-capture")
	if err := os.Rename(filepath.Join(r.dir, "traffic.pcap"), filepath.Join(r.dir, "traffic-before-restart.pcap")); err != nil {
		r.t.Fatal(err)
	}
	r.write("traffic.pcap", nil)
	r.command("docker", "restart", r.controller)
	r.until("restarted controller ready", func() bool { return r.tryCLI("status") != nil })
	r.command("docker", "start", r.name+"-capture")
	for _, id := range ids {
		snapshot := r.snapshot(id)
		if !snapshot.LastInform.IsZero() || snapshot.ReportedConfigVersion != "" {
			r.t.Fatal("observations survived restart")
		}
	}
	var statuses []controller.Status
	if err := json.Unmarshal(r.cli("status"), &statuses); err != nil {
		r.t.Fatal(err)
	}
	r.writeJSON("restart-cleared-status.json", statuses)
	for _, device := range statuses {
		if device.Pending != 0 {
			r.t.Fatal("queue survived restart")
		}
		if device.MAC == apID && device.DesiredConfigVersion != pendingVersion {
			r.t.Fatal("pending desired configuration did not survive restart")
		}
	}
	// Import forces the restarted process to serialize its in-memory devices.
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		r.t.Fatal(err)
	}
	r.write("reload-probe-key", []byte(hex.EncodeToString(key)))
	r.cli("import", "--mac=02:00:00:00:08:04", "--key-file=/state/reload-probe-key")
	after, err := os.ReadFile(filepath.Join(r.dir, "devices.json"))
	if err != nil {
		r.t.Fatal(err)
	}
	var oldState, newState []map[string]json.RawMessage
	if json.Unmarshal(before, &oldState) != nil || json.Unmarshal(after, &newState) != nil {
		r.t.Fatal("invalid saved state")
	}
	if len(oldState) != 3 || len(newState) != 4 {
		r.t.Fatal("persisted devices missing")
	}
	for index, device := range oldState {
		for _, field := range []string{"key", "desired_ap", "desired_switch", "desired_version", "baseline"} {
			if !bytes.Equal(device[field], newState[index][field]) {
				r.t.Fatal("durable identity or desired state changed")
			}
		}
	}
	for _, name := range emulators {
		r.command("docker", "unpause", name)
	}
	clearedWindowStart := time.Now()
	r.until("first AP snapshot after restart", func() bool {
		snapshot := r.snapshot(apID)
		return snapshot.LastInform.After(clearedWindowStart) && snapshot.ReportedConfigVersion == reportedBeforeRestart
	})
	firstInform := r.snapshot(apID).LastInform
	r.until("second AP snapshot after restart", func() bool {
		return r.snapshot(apID).LastInform.After(firstInform)
	})
	secondSnapshot := r.snapshot(apID)
	if secondSnapshot.ReportedConfigVersion != reportedBeforeRestart {
		r.t.Fatal("typed configuration queue replayed after restart")
	}
	r.writeJSON("restart-cleared-window.json", struct {
		ID                 network.DeviceID
		Start, Inform, End time.Time
	}{network.DeviceID(apID), clearedWindowStart, firstInform, time.Now()})
	for index, id := range ids {
		if id == apID {
			continue
		}
		var version network.ConfigVersion
		if err := json.Unmarshal(oldState[index]["desired_version"], &version); err != nil {
			r.t.Fatal(err)
		}
		r.until("fresh snapshot after restart", func() bool {
			snapshot := r.snapshot(id)
			return !snapshot.LastInform.IsZero() && snapshot.ReportedConfigVersion == version
		})
	}
	persistedAP := r.persistedDevice(apID).DesiredAP
	if persistedAP == nil {
		r.t.Fatal("restarted desired AP configuration is unavailable")
	}
	r.writeJSON("restart-requeue-ap.json", persistedAP)
	requeuedVersion := decodeLiveQueuedVersion(r.t, r.cli("apply", "ap", "--device="+apID, "--file=/state/restart-requeue-ap.json"))
	if requeuedVersion != pendingVersion || r.pending(apID) != 1 {
		r.t.Fatal("restart did not clear typed awaiting state for deliberate reconciliation")
	}
	r.recordOracle("resource-restart-requeue", apID, requeuedVersion)
	r.waitVersion(apID, requeuedVersion)
	r.writeJSON("restart-followup-radio.json", network.RadioConfig{ID: network.RadioID(pendingRadioID), Channel: network.Supplied(uint16(157))})
	followupVersion := decodeLiveQueuedVersion(r.t, r.cli("radio", "set", "--device="+apID, "--file=/state/restart-followup-radio.json"))
	r.oracleSetRadio(apID, pendingRadioID, 157)
	r.recordOracle("resource-restart-followup", apID, followupVersion)
	r.waitVersion(apID, followupVersion)
	r.write("devices-after.json", r.cli("devices"))
	r.socketOperations("restart", models, ids)
}

func (r *liveRun) addSecondAP(model liveModel, index int) (string, string) {
	// The restart probe occupies the next synthetic identity without an emulator.
	id := fmt.Sprintf("02:00:00:00:08:%02x", index+2)
	emulator := fmt.Sprintf("%s-device-%d", r.name, index)
	r.cli("adopt", "--mac="+id, "--file=/state/adopt.json")
	r.command("docker", "run", "-d", "--name", emulator, "--network", r.name, r.name+":emulator",
		"-inform", "http://controller:8080/inform", "-model", model.Model, "-mac", id,
		"-ip", fmt.Sprintf("192.0.2.%d", index+10), "-name", fmt.Sprintf("test-device-%d", index))
	r.until("second AP adoption", func() bool {
		snapshot := r.snapshot(id)
		return snapshot.Family == network.FamilyAP && snapshot.ReportedConfigVersion == "unifi-go-1"
	})
	baseline, err := os.ReadFile(filepath.Join(r.dir, "baseline-0.json"))
	if err != nil {
		r.t.Fatal(err)
	}
	r.write("baseline-3.json", baseline)
	r.loadOracleBaseline(3, id)
	r.write("second-ap-id", []byte(id))
	r.command("docker", "exec", r.controller, "/state/live-test", "-test.run=^TestLiveSecondAP$", "-test.v", "-test.timeout=4m")
	var applied struct {
		ID      network.DeviceID
		Version network.ConfigVersion
	}
	body, err := os.ReadFile(filepath.Join(r.dir, "applied-second-ap.json"))
	if err != nil || json.Unmarshal(body, &applied) != nil || applied.ID != network.DeviceID(id) || applied.Version == "" {
		r.t.Fatal("second AP applied result unavailable")
	}
	r.recordOracle("second-ap", id, applied.Version)
	r.waitVersion(id, applied.Version)
	return id, emulator
}

// TestLiveSecondAP configures the synthetic second AP through the public client.
func TestLiveSecondAP(t *testing.T) {
	idBody, err := os.ReadFile("/state/second-ap-id")
	if err != nil {
		t.Skip("isolated container helper")
	}
	var baseline network.BaselineImport
	body, err := os.ReadFile("/state/baseline-3.json")
	if err != nil || json.Unmarshal(body, &baseline) != nil || baseline.AP == nil {
		t.Fatal("second AP baseline unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	client := network.Dial("/runtime/control.sock")
	id := network.DeviceID(idBody)
	if err := client.ImportBaseline(ctx, id, baseline); err != nil {
		t.Fatal("second AP baseline import failed", err)
	}
	version, err := client.ApplyAP(ctx, id, baseline.AP.Clone())
	if err != nil {
		t.Fatal("second AP full configuration failed", err)
	}
	if err := os.WriteFile("/state/applied-second-ap.json", mustLiveJSON(t, struct {
		ID      network.DeviceID
		Version network.ConfigVersion
	}{id, version}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (r *liveRun) assertAmbiguousAPSelection() {
	before := r.readState()
	output, err := r.cliResult("wifi", "list")
	if err == nil || !bytes.Contains(output, []byte(string(network.AmbiguousDevice))) {
		r.t.Fatal("omitted device selected one of multiple access points")
	}
	if !bytes.Equal(before, r.readState()) {
		r.t.Fatal("ambiguous device selection changed controller state")
	}
}

func assertLiveWiFiCopy(t *testing.T, before, after configmap.Values, source, destination string) {
	t.Helper()
	sourceWireless := liveRecordPrefixes(after, "wireless.", source)
	destinationWireless := liveRecordPrefixes(after, "wireless.", destination)
	sourceAuth := liveRecordPrefixes(after, "aaa.", source)
	destinationAuth := liveRecordPrefixes(after, "aaa.", destination)
	if len(sourceWireless) != 2 || len(destinationWireless) != 2 || len(sourceAuth) != 2 || len(destinationAuth) != 2 {
		t.Fatal("dual-radio WiFi copy did not retain both wireless and authentication records")
	}
	if !maps.Equal(liveRecordFieldSet(after, sourceWireless, "parent"), liveRecordFieldSet(after, destinationWireless, "parent")) {
		t.Fatal("WiFi copy changed radio targets")
	}
	sourcePSKs := liveRecordFieldSet(after, sourceAuth, "wpa.psk")
	destinationPSKs := liveRecordFieldSet(after, destinationAuth, "wpa.psk")
	if len(sourcePSKs) != 1 || len(destinationPSKs) != 1 || maps.Equal(sourcePSKs, destinationPSKs) {
		t.Fatal("WiFi copy did not retain distinct source and destination credentials")
	}
	for key, value := range before {
		if strings.HasPrefix(key, "radio.") && after[key] != value {
			t.Fatal("WiFi copy changed radio policy")
		}
	}
	for _, test := range []struct {
		name, want string
	}{{source, "enabled"}, {destination, "enabled"}, {"synthetic-legacy", "disabled"}} {
		assertLiveNamedBSS(t, after, test.name, test.want)
	}
}

func assertLiveBSSPolicy(t *testing.T, values configmap.Values, enabled, disabled, legacy string) {
	t.Helper()
	for _, test := range []struct {
		name, want string
	}{{enabled, "enabled"}, {disabled, "disabled"}, {legacy, "disabled"}} {
		assertLiveNamedBSS(t, values, test.name, test.want)
	}
}

func assertLiveNamedBSS(t *testing.T, values configmap.Values, name, want string) {
	t.Helper()
	prefixes := liveRecordPrefixes(values, "aaa.", name)
	if len(prefixes) == 0 {
		t.Fatal("WiFi authentication policy is missing")
	}
	for _, prefix := range prefixes {
		if values[prefix+"bss_transition"] != want {
			t.Fatal("per-network BSS Transition policy changed")
		}
	}
}

func liveRecordPrefixes(values configmap.Values, namespace, name string) []string {
	var prefixes []string
	for key, value := range values {
		if strings.HasPrefix(key, namespace) && strings.HasSuffix(key, ".ssid") && value == name {
			prefixes = append(prefixes, strings.TrimSuffix(key, "ssid"))
		}
	}
	return prefixes
}

func liveRecordFieldSet(values configmap.Values, prefixes []string, field string) map[string]bool {
	result := make(map[string]bool)
	for _, prefix := range prefixes {
		result[values[prefix+field]] = true
	}
	return result
}

func (r *liveRun) verifyCapture(ids []string, models []liveModel) {
	state, err := os.ReadFile(filepath.Join(r.dir, "devices.json"))
	if err != nil {
		r.t.Fatal(err)
	}
	var devices []struct{ MAC, Key string }
	if json.Unmarshal(state, &devices) != nil {
		r.t.Fatal("invalid state")
	}
	keys := map[string]string{}
	for _, device := range devices {
		keys[device.MAC] = device.Key
	}
	output := r.command("tshark", "-r", filepath.Join(r.dir, "combined.pcap"), "-Y", "http.file_data", "-T", "fields", "-e", "frame.time_epoch", "-e", "http.file_data")
	type window struct {
		ID                 network.DeviceID
		Start, Inform, End time.Time
	}
	var expected []liveExpectation
	var windows []window
	for _, phase := range []string{"initial", "restart"} {
		for index := range models {
			body, err := os.ReadFile(filepath.Join(r.dir, fmt.Sprintf("expected-%s-%d.json", phase, index)))
			if err != nil {
				r.t.Fatal(err)
			}
			var item liveExpectation
			if json.Unmarshal(body, &item) != nil {
				r.t.Fatal("invalid expectation")
			}
			expected = append(expected, item)
			body, err = os.ReadFile(filepath.Join(r.dir, fmt.Sprintf("preview-%s-%d.json", phase, index)))
			if err != nil {
				r.t.Fatal(err)
			}
			var period window
			if json.Unmarshal(body, &period) != nil {
				r.t.Fatal("invalid preview interval")
			}
			if !period.Inform.After(period.Start) || !period.End.After(period.Inform) {
				r.t.Fatal("preview interval does not bracket a subsequent inform")
			}
			windows = append(windows, period)
		}
	}
	body, err := os.ReadFile(filepath.Join(r.dir, "restart-cleared-window.json"))
	if err != nil {
		r.t.Fatal(err)
	}
	var cleared window
	if json.Unmarshal(body, &cleared) != nil || !cleared.Inform.After(cleared.Start) || !cleared.End.After(cleared.Inform) {
		r.t.Fatal("restart queue-clear interval is invalid")
	}
	windows = append(windows, cleared)
	resourceExpectations, err := filepath.Glob(filepath.Join(r.dir, "expected-resource-*.json"))
	if err != nil {
		r.t.Fatal(err)
	}
	if len(resourceExpectations) == 0 {
		r.t.Fatal("expected-resource capture expectations are missing")
	}
	secondExpectations, err := filepath.Glob(filepath.Join(r.dir, "expected-second-ap.json"))
	if err != nil {
		r.t.Fatal(err)
	}
	if len(secondExpectations) == 0 {
		r.t.Fatal("expected-second-ap capture expectation is missing")
	}
	for _, path := range append(resourceExpectations, secondExpectations...) {
		body, err := os.ReadFile(path)
		if err != nil {
			r.t.Fatal(err)
		}
		var item liveExpectation
		if err := json.Unmarshal(body, &item); err != nil {
			r.t.Fatal("invalid resource capture expectation")
		}
		expected = append(expected, item)
	}
	uniqueExpected := make(map[string]liveExpectation)
	for _, item := range expected {
		key := string(item.ID) + ":" + string(item.Version)
		if previous, exists := uniqueExpected[key]; exists && (!maps.Equal(previous.Management, item.Management) || !maps.Equal(previous.System, item.System)) {
			r.t.Fatal("one expected version has conflicting configuration maps")
		}
		uniqueExpected[key] = item
	}
	expected = expected[:0]
	for _, item := range uniqueExpected {
		expected = append(expected, item)
	}
	matched := map[string]bool{}
	noops := make([]bool, len(windows))
	adopted := map[string]bool{}
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		stamp, encoded, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		seconds, err := strconv.ParseFloat(stamp, 64)
		if err != nil {
			r.t.Fatal("invalid capture time")
		}
		body, err := hex.DecodeString(strings.ReplaceAll(encoded, ":", ""))
		if err != nil || len(body) < 40 || !bytes.HasPrefix(body, []byte("TNBU")) {
			continue
		}
		id := net.HardwareAddr(body[8:14]).String()
		var payload struct {
			Type       string                `json:"_type"`
			Cmd        string                `json:"cmd"`
			Version    network.ConfigVersion `json:"cfgversion"`
			Management string                `json:"mgmt_cfg"`
			System     string                `json:"system_cfg"`
		}
		var packet *inform.Packet
		decoded := false
		for _, key := range []string{keys[id], inform.DefaultKey} {
			candidate, err := inform.Decode(body, key)
			if err == nil && json.Unmarshal(candidate.Payload, &payload) == nil {
				packet = candidate
				decoded = true
				break
			}
		}
		if !decoded {
			r.t.Fatal("captured encrypted packet did not decrypt to a valid payload")
		}
		count++
		if bytes.Contains(packet.Payload, []byte("must-not-replay")) {
			r.t.Fatal("queued command replayed")
		}
		if payload.Cmd == "set-adopt" {
			adopted[id] = true
		}
		for index, period := range windows {
			if network.DeviceID(id) != period.ID || seconds <= float64(period.Start.UnixNano())/1e9 || seconds >= float64(period.End.UnixNano())/1e9 {
				continue
			}
			if payload.Type == "setparam" {
				r.t.Fatal("preview interval delivered setparam")
			}
			if payload.Type == "noop" && seconds >= float64(period.Inform.UnixNano())/1e9 {
				noops[index] = true
			}
		}
		if payload.Type != "setparam" {
			continue
		}
		for _, item := range expected {
			if network.DeviceID(id) != item.ID || payload.Version != item.Version {
				continue
			}
			management, err := configmap.Parse(payload.Management)
			if err != nil {
				r.t.Fatal("invalid delivered management map")
			}
			system, err := configmap.Parse(payload.System)
			if err != nil {
				r.t.Fatal("invalid delivered system map")
			}
			// Typed transport replaces only these connection and version metadata records.
			if management["cfgversion"] != string(item.Version) || management["authkey"] != keys[id] || management["inform_url"] != "http://controller:8080/inform" {
				r.t.Fatal("delivered connection metadata differs")
			}
			for _, key := range []string{"cfgversion", "authkey", "inform_url"} {
				delete(management, key)
				delete(item.Management, key)
			}
			if !maps.Equal(management, item.Management) || !maps.Equal(system, item.System) {
				r.t.Fatal("full delivered maps changed omitted policy")
			}
			matched[string(item.ID)+":"+string(item.Version)] = true
		}
	}
	for _, id := range ids {
		if !adopted[id] {
			r.t.Fatal("capture lacks adoption")
		}
	}
	if len(matched) != len(expected) {
		r.t.Fatal("capture lacks applied full maps")
	}
	for _, seen := range noops {
		if !seen {
			r.t.Fatal("capture lacks encrypted preview noop")
		}
	}
	r.writeJSON("capture-summary.json", struct{ Messages, AppliedMaps, PreviewNoops int }{count, len(matched), len(noops)})
}

func (r *liveRun) snapshot(id string) network.DeviceSnapshot {
	var snapshot network.DeviceSnapshot
	data := r.tryCLI("device", "--device="+id)
	if data != nil && json.Unmarshal(data, &snapshot) != nil {
		r.t.Fatal("invalid snapshot output")
	}
	return snapshot
}

func (r *liveRun) cli(args ...string) []byte {
	return r.command("docker", append([]string{"exec", r.controller, "/unifi-go"}, append(args, "--socket=/runtime/control.sock")...)...)
}

func (r *liveRun) cliResult(args ...string) ([]byte, error) {
	cmd := exec.CommandContext(r.ctx, "docker", append([]string{"exec", r.controller, "/unifi-go"}, append(args, "--socket=/runtime/control.sock")...)...)
	cmd.Dir = r.root
	return r.executeResult(cmd)
}

func (r *liveRun) tryCLI(args ...string) []byte {
	cmd := exec.CommandContext(r.ctx, "docker", append([]string{"exec", r.controller, "/unifi-go"}, append(args, "--socket=/runtime/control.sock")...)...)
	output, err := cmd.Output()
	if err != nil {
		return nil
	}
	return output
}

func (r *liveRun) until(label string, ready func() bool) {
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		select {
		case <-r.ctx.Done():
			r.t.Fatal("live run canceled")
		case <-time.After(time.Second):
		}
	}
	r.t.Fatal("timed out: " + label)
}

func (r *liveRun) command(name string, args ...string) []byte {
	cmd := exec.CommandContext(r.ctx, name, args...)
	cmd.Dir = r.root
	return r.execute(cmd)
}

func (r *liveRun) execute(cmd *exec.Cmd) []byte {
	output, err := r.executeResult(cmd)
	if err != nil {
		r.t.Fatalf("%s failed; private command-%03d.log: %v", filepath.Base(cmd.Path), r.commands, err)
	}
	return output
}

func (r *liveRun) executeResult(cmd *exec.Cmd) ([]byte, error) {
	output, err := cmd.CombinedOutput()
	r.commands++
	exitCode := -1
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}
	r.writeJSON(fmt.Sprintf("command-%03d.json", r.commands), struct {
		Args     []string
		ExitCode int
	}{cmd.Args, exitCode})
	r.write(fmt.Sprintf("command-%03d.log", r.commands), output)
	return output, err
}

func (r *liveRun) summarizeLogs(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "docker", "logs", name).CombinedOutput()
	if err != nil {
		r.t.Errorf("read isolated container logs: %v", err)
		return
	}
	r.writeJSON(name+"-log-summary.json", struct{ Bytes, Lines, ErrorMarkers int }{
		len(output), bytes.Count(output, []byte{'\n'}), bytes.Count(bytes.ToLower(output), []byte("error")),
	})
}

func (r *liveRun) cleanup(args ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	if _, err := cmd.CombinedOutput(); err != nil {
		r.t.Errorf("isolated Docker cleanup failed: %v", err)
	}
}

func (r *liveRun) write(name string, data []byte) {
	if err := os.WriteFile(filepath.Join(r.dir, name), data, 0o600); err != nil {
		r.t.Fatal(err)
	}
}

func (r *liveRun) writeJSON(name string, value any) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		r.t.Fatal(err)
	}
	r.write(name, append(data, '\n'))
}

func (r *liveRun) manifest() {
	var lines []string
	err := filepath.WalkDir(r.dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.Chmod(path, 0o700)
		}
		if entry.Name() == "SHA256SUMS" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return err
		}
		relative, err := filepath.Rel(r.dir, path)
		if err != nil {
			return err
		}
		lines = append(lines, fmt.Sprintf("%x  %s", sha256.Sum256(data), relative))
		return nil
	})
	if err != nil {
		r.t.Error(err)
		return
	}
	r.write("SHA256SUMS", []byte(strings.Join(lines, "\n")+"\n"))
}
