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
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jamesbraid/unifi-emu/inform"

	"goodkind.io/unifi-go/internal/configmap"
	"goodkind.io/unifi-go/network"
)

const liveEmulatorImage = "ghcr.io/jamesbraid/unifi-emu:0.5.5"

type liveRun struct {
	t                           *testing.T
	ctx                         context.Context
	root, dir, name, controller string
	commands                    int
	interrupted                 context.Context
}

type liveModel struct {
	Model  string         `json:"model"`
	Type   string         `json:"type"`
	Ports  []inform.Port  `json:"ports"`
	Radios []inform.Radio `json:"radios"`
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
	r := &liveRun{t: t, ctx: ctx, root: root, dir: dir, name: filepath.Base(dir), interrupted: signalContext}
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
	r.write("devices-before.json", r.cli("devices"))
	r.cli("clients", "--device="+ids[0])
	for _, id := range ids[1:] {
		r.cli("ports", "--device="+id)
	}
	r.restart(ids, emulators)
	r.command("docker", "stop", "-t", "5", capture)
	r.command("mergecap", "-w", filepath.Join(r.dir, "combined.pcap"), filepath.Join(r.dir, "traffic-before-restart.pcap"), filepath.Join(r.dir, "traffic.pcap"))
	r.verifyCapture(ids, models)
	r.write("result.txt", []byte("PASS: live patched emulator adoption, typed Apply, observations, restart, encrypted capture\nNo physical forwarding, PoE power, or client association proof.\n"))
	if os.Getenv("UNIFI_LIVE_CHILD_PHASE") == "" {
		r.verifyInterruptions()
	}
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
		for _, suffix := range []string{"-controller", "-capture", "-device-0", "-device-1", "-device-2"} {
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
	for _, suffix := range []string{"-device-0", "-device-1", "-device-2", "-capture", "-controller"} {
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
			// The second captured radio becomes a synthetic peer with absent BSS policy.
			param.System["wireless.2.ssid"], param.System["aaa.2.ssid"] = "synthetic-peer", "synthetic-peer"
			delete(param.System, "aaa.2.bss_transition")
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
			baseline.AP = &network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{
				{Name: "fixture-wifi", Bands: network.Supplied([]network.RadioBand{network.Band5GHz})},
				{Name: "synthetic-peer", Bands: network.Supplied([]network.RadioBand{network.Band2GHz})},
			})}
		} else {
			baseline.Switch = &network.SwitchConfig{Ports: network.Supplied([]network.SwitchPortConfig{{Index: 2}, {Index: 3}, {Index: 4}, {Index: 5}})}
		}
		r.writeJSON(fmt.Sprintf("baseline-%d.json", index), baseline)
	}
	r.socketOperations("initial")
}

func (r *liveRun) socketOperations(phase string) {
	if err := os.Chmod(filepath.Join(r.dir, "live-test"), 0o700); err != nil {
		r.t.Fatal(err)
	}
	r.command("docker", "exec", "-e", "UNIFI_LIVE_SOCKET_PHASE="+phase, r.controller,
		"/state/live-test", "-test.run=^TestLiveSocketOperations$", "-test.v", "-test.timeout=4m")
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
			{Name: "fixture-wifi", BSSTransition: network.Supplied(network.BSSTransitionDisabled)},
			{Name: "synthetic-peer"},
		})}
		switchRequest := network.SwitchConfig{Ports: network.Supplied([]network.SwitchPortConfig{
			{Index: 2, Enabled: network.Supplied(false)}, {Index: 3}, {Index: 4}, {Index: 5},
		})}
		if phase == "restart" {
			apRequest = network.APConfig{Radios: network.Supplied([]network.RadioConfig{{Band: network.Band5GHz, Channel: network.Supplied(uint16(157))}})}
			switchRequest = network.SwitchConfig{Ports: network.Supplied([]network.SwitchPortConfig{
				{Index: 2}, {Index: 3, Enabled: network.Supplied(false)}, {Index: 4}, {Index: 5},
			})}
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
		management, err := configmap.Parse(baseline.Config.Management)
		if err != nil {
			t.Fatal(err)
		}
		system, err := configmap.Parse(baseline.Config.System)
		if err != nil {
			t.Fatal(err)
		}
		if device.Family == network.FamilyAP {
			system["aaa.1.bss_transition"] = "disabled"
			if phase == "restart" {
				system["radio.1.channel"] = "157"
			}
		} else {
			system["switch.port.2.status"] = "disabled"
			if phase == "restart" {
				system["switch.port.3.status"] = "disabled"
			}
		}
		expected := struct {
			ID                 network.DeviceID
			Version            network.ConfigVersion
			Management, System configmap.Values
		}{device.ID, version, management, system}
		if err := os.WriteFile(fmt.Sprintf("/state/expected-%s-%d.json", phase, index), mustLiveJSON(t, expected), 0o600); err != nil {
			t.Fatal(err)
		}
		index++
	}
	if index != 3 {
		t.Fatal("live adopted inventory does not contain three devices")
	}
}

func mustLiveJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func (r *liveRun) restart(ids, emulators []string) {
	for _, name := range emulators {
		r.command("docker", "pause", name)
	}
	r.interruptCheckpoint("paused")
	before, err := os.ReadFile(filepath.Join(r.dir, "devices.json"))
	if err != nil {
		r.t.Fatal(err)
	}
	r.write("state-before-restart.json", before)
	r.write("pending.json", []byte(`{"_type":"cmd","cmd":"must-not-replay"}`))
	for _, id := range ids {
		r.cli("send", "--mac="+id, "--file=/state/pending.json")
	}
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
	var status []struct {
		Pending int `json:"pending"`
	}
	if err := json.Unmarshal(r.cli("status"), &status); err != nil {
		r.t.Fatal(err)
	}
	for _, device := range status {
		if device.Pending != 0 {
			r.t.Fatal("queue survived restart")
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
	for index, id := range ids {
		var version network.ConfigVersion
		if err := json.Unmarshal(oldState[index]["desired_version"], &version); err != nil {
			r.t.Fatal(err)
		}
		r.until("fresh snapshot after restart", func() bool {
			snapshot := r.snapshot(id)
			return !snapshot.LastInform.IsZero() && snapshot.ReportedConfigVersion == version
		})
	}
	r.write("devices-after.json", r.cli("devices"))
	r.socketOperations("restart")
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
	type expectation struct {
		ID                 network.DeviceID
		Version            network.ConfigVersion
		Management, System configmap.Values
	}
	type window struct {
		ID                 network.DeviceID
		Start, Inform, End time.Time
	}
	var expected []expectation
	var windows []window
	for _, phase := range []string{"initial", "restart"} {
		for index := range models {
			body, err := os.ReadFile(filepath.Join(r.dir, fmt.Sprintf("expected-%s-%d.json", phase, index)))
			if err != nil {
				r.t.Fatal(err)
			}
			var item expectation
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
		packet, err := inform.Decode(body, keys[id])
		if err != nil {
			packet, err = inform.Decode(body, inform.DefaultKey)
		}
		if err != nil {
			r.t.Fatal("captured encrypted packet did not decrypt")
		}
		count++
		if bytes.Contains(packet.Payload, []byte("must-not-replay")) {
			r.t.Fatal("queued command replayed")
		}
		var payload struct {
			Type       string                `json:"_type"`
			Cmd        string                `json:"cmd"`
			Version    network.ConfigVersion `json:"cfgversion"`
			Management string                `json:"mgmt_cfg"`
			System     string                `json:"system_cfg"`
		}
		if json.Unmarshal(packet.Payload, &payload) != nil {
			r.t.Fatal("invalid capture payload")
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
	if err != nil {
		r.t.Fatalf("%s failed; private command-%03d.log: %v", filepath.Base(cmd.Path), r.commands, err)
	}
	return output
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
