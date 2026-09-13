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
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jamesbraid/unifi-emu/inform"

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
				Version string `json:"cfgversion"`
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
			if !bytes.Contains(state, []byte("No such")) {
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
		return
	}
	r.command("docker", "pull", liveEmulatorImage)
	r.command("docker", "pull", "nicolaka/netshoot:v0.14")
	r.command("docker", "build", "-t", r.name+":controller", r.root)
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
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		r.t.Fatal(err)
	}
	r.write("wifi-secret", []byte(hex.EncodeToString(secret)))
	r.write("ap.json", []byte(`{"country_code":840,"networks":[{"name":"E2E-Lab","enabled":true,"vlan":20,"bands":["2.4ghz","5ghz"],"bss_transition":"enabled","security":{"mode":"wpa2-personal","psk":"/state/wifi-secret"}}],"radios":[{"band":"2.4ghz","enabled":true,"channel":6,"width_mhz":20,"power":{"mode":"explicit","dbm":10}},{"band":"5ghz","enabled":true,"channel":44,"width_mhz":40,"power":{"mode":"explicit","dbm":12}}]}`))
	for index, id := range ids {
		family, file := "ap", "ap.json"
		if index > 0 {
			family, file = "switch", fmt.Sprintf("switch-%d.json", index)
			config := suppliedSwitchConfig(
				suppliedSwitchPort(1, true, 20, []network.VLANID{}, network.PoEOff),
				suppliedSwitchPort(uint16(models[index].Ports[len(models[index].Ports)-1].PortIdx), true, 1, []network.VLANID{20}, ""),
			)
			r.writeJSON(file, config)
		}
		var queued struct {
			Version network.ConfigVersion `json:"version"`
		}
		if err := json.Unmarshal(r.cli("apply", family, "--device="+id, "--file=/state/"+file), &queued); err != nil {
			r.t.Fatal(err)
		}
		if queued.Version == "" {
			r.t.Fatal("Apply returned an empty version")
		}
		r.until("applied version reported", func() bool { return r.snapshot(id).ReportedConfigVersion == queued.Version })
		snapshot := r.snapshot(id)
		if index == 0 {
			if snapshot.AP == nil || len(snapshot.AP.Radios) != 2 {
				r.t.Fatal("public AP inventory is incomplete")
			}
			bands := map[network.RadioBand]bool{}
			if len(snapshot.AP.Clients) != 0 {
				r.t.Fatal("emulator unexpectedly claims associated clients")
			}
			for _, radio := range snapshot.AP.Radios {
				if bands[radio.Band] || (radio.Band != network.Band2GHz && radio.Band != network.Band5GHz) {
					r.t.Fatal("public AP radio bands differ from selected inventory")
				}
				bands[radio.Band] = true
				channel, width, power := uint16(6), network.Width20, 10
				if radio.Band == network.Band5GHz {
					channel, width, power = 44, network.Width40, 12
				}
				if radio.Channel == nil || *radio.Channel != channel || radio.WidthMHz == nil || *radio.WidthMHz != width || radio.PowerDBm == nil || *radio.PowerDBm != power {
					r.t.Fatal("AP radio report does not match applied settings")
				}
			}
		} else {
			if snapshot.Switch == nil || len(snapshot.Switch.Ports) != len(models[index].Ports) {
				r.t.Fatal("public switch inventory is incomplete")
			}
			expected := map[uint16]bool{}
			for _, port := range models[index].Ports {
				expected[uint16(port.PortIdx)] = true
			}
			for _, port := range snapshot.Switch.Ports {
				if !expected[port.Index] {
					r.t.Fatal("public switch port indexes differ from selected inventory")
				}
				delete(expected, port.Index)
				if port.Up == nil || !*port.Up || port.SpeedMbps == nil || *port.SpeedMbps != 1000 || port.FullDuplex == nil || !*port.FullDuplex {
					r.t.Fatal("public switch link state differs from emulator report")
				}
				if port.Index == 1 {
					if port.NativeVLAN == nil || *port.NativeVLAN != 20 || port.TaggedVLANs == nil || len(port.TaggedVLANs) != 0 || port.PoEMode != network.PoEOff {
						r.t.Fatal("public switch access VLAN or PoE observation differs from patched report")
					}
				} else if port.Index == uint16(models[index].Ports[len(models[index].Ports)-1].PortIdx) {
					if port.NativeVLAN == nil || *port.NativeVLAN != 1 || !slices.Equal(port.TaggedVLANs, []network.VLANID{20}) || port.PoEMode != "" {
						r.t.Fatal("public switch trunk observation differs from patched report")
					}
				} else if port.NativeVLAN != nil || port.PoEMode != "" {
					r.t.Fatal("unconfigured port acquired an invented observation")
				}
			}
		}
	}
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
	r.write("pending.json", []byte(`{"_type":"setparam","cfgversion":"must-not-replay","mgmt_cfg":"cfgversion=must-not-replay\n","system_cfg":"sshd.status=enabled\n"}`))
	for _, id := range ids {
		r.cli("send", "--mac="+id, "--file=/state/pending.json")
	}
	r.command("docker", "restart", r.controller)
	r.until("restarted controller ready", func() bool { return r.tryCLI("status") != nil })
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
		for _, field := range []string{"key", "desired_ap", "desired_switch", "desired_version"} {
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
}

func (r *liveRun) verifyCapture(ids []string, models []liveModel) {
	state, err := os.ReadFile(filepath.Join(r.dir, "devices.json"))
	if err != nil {
		r.t.Fatal(err)
	}
	var devices []struct{ MAC, Key string }
	if err := json.Unmarshal(state, &devices); err != nil {
		r.t.Fatal(err)
	}
	keys := map[string]string{}
	for _, device := range devices {
		keys[device.MAC] = device.Key
	}
	output := r.command("tshark", "-r", filepath.Join(r.dir, "traffic.pcap"), "-Y", "http.file_data", "-T", "fields", "-e", "http.file_data")
	adopted, configured, reflected := map[string]bool{}, map[string]bool{}, map[string]bool{}
	uplinks := map[string]int{}
	for index, id := range ids[1:] {
		uplinks[id] = models[index+1].Ports[len(models[index+1].Ports)-1].PortIdx
	}
	secret, err := os.ReadFile(filepath.Join(r.dir, "wifi-secret"))
	if err != nil {
		r.t.Fatal(err)
	}
	count := 0
	for _, line := range strings.Fields(string(output)) {
		body, err := hex.DecodeString(strings.ReplaceAll(line, ":", ""))
		if err != nil {
			r.t.Fatal("invalid capture hex")
		}
		if len(body) < 40 || !bytes.HasPrefix(body, []byte("TNBU")) {
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
			r.t.Fatal("pending configuration replayed after restart")
		}
		var payload struct {
			Type   string `json:"_type"`
			Cmd    string `json:"cmd"`
			System string `json:"system_cfg"`
			Ports  []struct {
				Index  int    `json:"port_idx"`
				Native int    `json:"native_vlan"`
				PoE    string `json:"poe_mode"`
				Tagged []int  `json:"tagged_vlans"`
			} `json:"port_table"`
			Radios []struct {
				Channel int `json:"channel"`
			} `json:"radio_table"`
		}
		if json.Unmarshal(packet.Payload, &payload) != nil {
			r.t.Fatal("invalid captured JSON")
		}
		if payload.Cmd == "set-adopt" {
			adopted[id] = true
		}
		if payload.Type == "setparam" {
			values := map[string]string{}
			for _, record := range strings.Split(payload.System, "\n") {
				key, value, ok := strings.Cut(record, "=")
				if ok {
					values[key] = value
				}
			}
			if id == ids[0] {
				expected := map[string]string{"radio.1.channel": "44", "radio.2.channel": "6", "radio.1.ieee_mode": "11naht40", "radio.2.ieee_mode": "11nght20", "radio.1.txpower": "12", "radio.2.txpower": "10"}
				for slot := 1; slot <= 2; slot++ {
					prefix := fmt.Sprintf("aaa.%d.", slot)
					for suffix, value := range map[string]string{"wpa": "2", "br.devname": "br0.20", "wpa.1.pairwise": "CCMP", "wpa.key.1.mgmt": "WPA-PSK", "wpa.psk": string(secret)} {
						expected[prefix+suffix] = value
					}
				}
				configured[id] = configured[id] || liveRecordsMatch(values, expected)
			} else {
				expected := map[string]string{"switch.port.1.pvid": "20", "switch.port.1.poe": "shutdown", "switch.vlan.1.id": "1", "switch.vlan.2.id": "20", "switch.vlan.2.port.1.mode": "untagged", fmt.Sprintf("switch.port.%d.pvid", uplinks[id]): "1", fmt.Sprintf("switch.vlan.2.port.%d.mode", uplinks[id]): "tagged"}
				configured[id] = configured[id] || liveRecordsMatch(values, expected)
			}
		}
		access, uplink := false, false
		for _, port := range payload.Ports {
			if port.Index == 1 && port.Native == 20 && port.PoE == "off" {
				access = true
			}
			if port.Index == uplinks[id] && port.Native == 1 && len(port.Tagged) == 1 && port.Tagged[0] == 20 {
				uplink = true
			}
		}
		reflected[id] = reflected[id] || (access && uplink)
		for _, radio := range payload.Radios {
			if radio.Channel == 44 {
				reflected[id] = true
			}
		}
	}
	for _, id := range ids {
		if !adopted[id] || !configured[id] || !reflected[id] {
			r.t.Fatalf("capture evidence incomplete for synthetic device %s: adoption=%t config=%t reflection=%t", id, adopted[id], configured[id], reflected[id])
		}
	}
	r.writeJSON("capture-summary.json", struct {
		Messages                       int
		Adopted, Configured, Reflected map[string]bool
	}{count, adopted, configured, reflected})
}

func liveRecordsMatch(values, expected map[string]string) bool {
	for key, value := range expected {
		if values[key] != value {
			return false
		}
	}
	return true
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
