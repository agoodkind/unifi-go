package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jamesbraid/unifi-emu/inform"
	"goodkind.io/unifi-go/internal/controller"
	"goodkind.io/unifi-go/internal/informmodel"
	"goodkind.io/unifi-go/network"
)

func testCommandAndBaselineOwnership(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef" // gitleaks:allow
	const id network.DeviceID = "02:00:00:00:00:61"
	state := filepath.Join(t.TempDir(), "state.json")
	baseline := typedSeedBaseline(t, network.FamilySwitch, "operator-version")
	baseline.Config.System = strings.ReplaceAll(baseline.Config.System, "unifi.idp=enabled\n", "unifi.idp=operator\n")
	baseline.Config.System = strings.ReplaceAll(baseline.Config.System, "unifi.feature.always_send_crash_logs=enabled\n", "unifi.feature.always_send_crash_logs=operator\n")
	baseline.Config.System += "switch.port.1.status=disabled\nswitch.port.1.pvid=20\n"
	config := typedSwitchFixture()
	writeTypedJSON(t, state, []controller.Device{{MAC: string(id), Key: key, Baseline: baseline, DesiredSwitch: &config, DesiredVersion: "stale", SSHUsername: "metadata-only", SSHPasswordHash: "$6$synthetic$stored-hash"}})
	c := openTypedController(t, state)
	client := network.Dial(startTypedSocket(t, c))
	poe := uint64(1)
	report := informmodel.Report{Type: "usw", PortTable: []informmodel.Port{{Index: 1, Interface: "eth0", PoECaps: &poe}}, SwitchCaps: &informmodel.SwitchCapabilities{VLANCaps: &poe}}
	typedExchange(t, c, id, key, report, false)
	raw := network.Config{Version: "raw", Management: "z=last\n\na=first\n", System: "unknown.security=operator\nrepeat=one\nrepeat=two\nlabel=雪\n"}
	if _, err := client.ApplyConfig(t.Context(), id, raw); err != nil {
		t.Fatal(err)
	}
	persisted := readTransportDevice(t, state)
	if persisted.Baseline == nil || persisted.Baseline.Config != raw || persisted.Baseline.TypedReady || len(persisted.Baseline.Bindings) != 0 || persisted.DesiredSwitch != nil || persisted.DesiredAP != nil || persisted.DesiredVersion != "" {
		t.Fatal("raw application retained typed ownership or changed bytes")
	}
	_, err := client.ApplySwitch(t.Context(), id, network.SwitchConfig{})
	assertControlFailure(t, err, network.BaselineUnusable, "")
	before, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []network.BaselineImport{
		{Config: raw, Switch: &config},
		{Config: network.Config{Version: "partial", Management: "a=b\n"}, Switch: &config},
		{Config: baseline.Config, AP: &network.APConfig{}, Switch: &config},
		{Config: baseline.Config, AP: &network.APConfig{}},
		{Config: baseline.Config, Switch: &network.SwitchConfig{Ports: network.Supplied([]network.SwitchPortConfig{{Index: 9}})}},
	} {
		if err := client.ImportBaseline(t.Context(), id, invalid); err == nil {
			t.Fatal("invalid baseline accepted")
		}
		after, err := os.ReadFile(state)
		if err != nil || !bytes.Equal(before, after) || c.Status()[0].Pending != 1 {
			t.Fatal("invalid import changed bytes or queued reply")
		}
	}
	if err := client.ImportBaseline(t.Context(), id, network.BaselineImport{Config: baseline.Config, Switch: &config}); err != nil {
		t.Fatal(err)
	}
	persisted = readTransportDevice(t, state)
	if persisted.Baseline.Config != baseline.Config || !persisted.Baseline.TypedReady || len(persisted.Baseline.Bindings) != 1 || persisted.DesiredVersion != baseline.Config.Version || persisted.LastSetParam.ConfigVersion != "raw" || c.Status()[0].Pending != 1 {
		t.Fatal("import changed delivery or failed to establish ownership")
	}
	if reply := typedExchange(t, c, id, key, report, false); reply.ManagementConfig != raw.Management || reply.SystemConfig != raw.System || reply.ConfigVersion != string(raw.Version) {
		t.Fatal("import changed queued raw reply")
	}
	command := network.Command{Name: "operator-unfamiliar-command", Parameters: map[string]json.RawMessage{"nested": json.RawMessage(`{"enabled":true,"items":[1,"雪",null]}`), "interval": json.RawMessage(`{"operator":true}`)}}
	if err := client.SendCommand(t.Context(), id, command); err != nil {
		t.Fatal(err)
	}
	reply := typedExchange(t, c, id, key, report, true)
	if reply.Type != controller.ReplyCommand || string(reply.Command) != command.Name || !reflect.DeepEqual(reply.Parameters, command.Parameters) {
		t.Fatal("arbitrary command name or structured parameters changed")
	}
	if readTransportDevice(t, state).Baseline.Config != baseline.Config {
		t.Fatal("command replaced baseline")
	}
	for _, name := range []string{"_type", "cmd", "server_time_in_utc"} {
		if err := client.SendCommand(t.Context(), id, network.Command{Name: "operator-command", Parameters: map[string]json.RawMessage{name: json.RawMessage(`1`)}}); err == nil {
			t.Fatal("reserved parameter accepted")
		}
	}
	if err := client.SendCommand(t.Context(), id, network.Command{Name: "set-adopt", Parameters: map[string]json.RawMessage{"key": json.RawMessage(`"invalid"`), "uri": json.RawMessage(`"invalid"`)}}); err == nil {
		t.Fatal("invalid adoption command accepted")
	}
	if err := c.Queue(string(id), controller.Reply{Type: controller.ReplyCommand, Command: controller.CommandSetAdopt, Key: key, URI: "http://192.0.2.1/inform", Parameters: map[string]json.RawMessage{"key": json.RawMessage(`null`)}}); err == nil {
		t.Fatal("null parameter overrode validated adoption key")
	}
	if err := client.SendCommand(t.Context(), id, command); err != nil {
		t.Fatal(err)
	}
	reloaded := openTypedController(t, state)
	if reply := typedExchange(t, reloaded, id, key, report, true); reply.Type != controller.ReplyNoop {
		t.Fatal("command replayed after restart")
	}
	restarted := network.Dial(startTypedSocket(t, reloaded))
	if _, err := restarted.ApplySwitch(t.Context(), id, network.SwitchConfig{}); err != nil {
		t.Fatal(err)
	}
	typed := typedExchange(t, reloaded, id, key, report, true)
	if !strings.Contains(typed.SystemConfig, "unifi.idp=operator\n") || !strings.Contains(typed.SystemConfig, "unifi.feature.always_send_crash_logs=operator\n") || strings.Contains(typed.SystemConfig, "sshd.") {
		t.Fatal("typed delivery selected policy")
	}
}

func testExplicitAdoptionSSH(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "requested"}[explicit], func(t *testing.T) {
			const id network.DeviceID = "02:00:00:00:00:62"
			directory := t.TempDir()
			state := filepath.Join(directory, "state.json")
			c := openTypedController(t, state)
			socket := startTypedSocket(t, c)
			template := filepath.Join(directory, "template.json")
			writeTypedJSON(t, template, controller.Reply{Type: controller.ReplySetparam, ManagementConfig: "cfgversion=operator\n", SystemConfig: "operator=雪\n"})
			args := []string{"adopt", "--mac", string(id), "--file", template, "--socket", socket}
			if explicit {
				args = append(args, "--setup-ssh")
			}
			if err := run(t.Context(), args, io.Discard); err != nil {
				t.Fatal(err)
			}
			device := readTransportDevice(t, state)
			if (device.SSHPasswordHash != "") != explicit || (device.SSHUsername != "") != explicit || (device.SSHPassword != "") != explicit {
				t.Fatal("adoption SSH ownership did not match explicit request")
			}
			transition := typedExchange(t, c, id, inform.DefaultKey, informmodel.Report{}, false)
			if transition.Command != controller.CommandSetAdopt || transition.Key != device.NextKey {
				t.Fatal("adoption key transition changed")
			}
			provision := typedExchange(t, c, id, device.NextKey, informmodel.Report{}, true)
			if strings.Contains(provision.SystemConfig, "sshd.status=enabled\n") != explicit || !strings.Contains(provision.SystemConfig, "operator=雪\n") {
				t.Fatal("adoption selected SSH without explicit request or lost operator policy")
			}
		})
	}
}

func readTransportDevice(t *testing.T, state string) controller.Device {
	t.Helper()
	body, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	var devices []controller.Device
	if err := json.Unmarshal(body, &devices); err != nil || len(devices) != 1 {
		t.Fatal("invalid persisted transport fixture")
	}
	return devices[0]
}

func testImportAPIdentities(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef" // gitleaks:allow
	const id network.DeviceID = "02:00:00:00:00:63"
	state := filepath.Join(t.TempDir(), "state.json")
	_, baseline := typedBSSFixture(t, "/nonexistent/operator-secret", "imported")
	writeTypedJSON(t, state, []controller.Device{{MAC: string(id), Key: key}})
	c := openTypedController(t, state)
	socket := startTypedSocket(t, c)
	client := network.Dial(socket)
	report := informmodel.Report{Type: "uap", RadioTable: []informmodel.Radio{{Name: "wifi0", Radio: "ng"}, {Name: "wifi1", Radio: "na"}}}
	typedExchange(t, c, id, key, report, false)
	projection := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{{Name: "fixture-legacy", Bands: network.Supplied([]network.RadioBand{network.Band2GHz, network.Band5GHz})}})}
	for _, invalid := range []network.BaselineImport{
		{Config: baseline.Config, AP: &network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{{Name: "fixture-legacy"}})}},
		{Config: network.Config{Version: baseline.Config.Version, Management: baseline.Config.Management, System: baseline.Config.System + "wireless.99.ssid=fixture-legacy\nwireless.99.parent=wifi0\nwireless.99.devname=duplicate\n"}, AP: &projection},
	} {
		if err := client.ImportBaseline(t.Context(), id, invalid); err == nil {
			t.Fatal("incomplete or ambiguous AP identity accepted")
		}
		if readTransportDevice(t, state).Baseline != nil || c.Status()[0].Pending != 0 {
			t.Fatal("invalid AP identity changed controller state")
		}
	}
	importFile := filepath.Join(t.TempDir(), "baseline.json")
	for _, body := range [][]byte{
		[]byte(`{"config":{"version":"bad","management":"key=\ud800","system":"key=value"}}`),
		append([]byte(`{"config":{"version":"bad","management":"key=`), append([]byte{0xff}, []byte(`","system":"key=value"}}`)...)...),
	} {
		writeTypedFixture(t, importFile, body)
		if err := run(t.Context(), []string{"baseline-import", "--device", string(id), "--file", importFile, "--socket", socket}, io.Discard); err == nil {
			t.Fatal("CLI baseline import normalized invalid Unicode")
		}
	}
	writeTypedJSON(t, importFile, network.BaselineImport{Config: baseline.Config, AP: &projection})
	if err := run(t.Context(), []string{"baseline-import", "--device", string(id), "--file", importFile, "--socket", socket}, io.Discard); err != nil {
		t.Fatal(err)
	}
	device := readTransportDevice(t, state)
	if device.Baseline.Config != baseline.Config || device.LastSetParam != nil || len(device.Baseline.Bindings) != 2 || len(device.Baseline.Bindings[0].Prefixes) < 4 {
		t.Fatal("AP import lost exact bytes or per-radio dependent bindings")
	}
	if _, err := client.ApplyAP(t.Context(), id, network.APConfig{CountryCode: network.Supplied(uint16(124))}); err != nil {
		t.Fatal(err)
	}
	reply := typedExchange(t, c, id, key, report, true)
	if !strings.Contains(reply.SystemConfig, "radio.countrycode=124\n") || !strings.Contains(reply.SystemConfig, "aaa.1.bss_transition=enabled\n") {
		t.Fatal("unrelated typed change did not preserve imported policy")
	}
	commandFile := filepath.Join(t.TempDir(), "command.json")
	writeTypedJSON(t, commandFile, network.Command{Name: "operator-command", Parameters: map[string]json.RawMessage{"value": json.RawMessage(`false`)}})
	if err := run(t.Context(), []string{"command", "--device", string(id), "--file", commandFile, "--socket", socket}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if reply := typedExchange(t, c, id, key, report, false); string(reply.Command) != "operator-command" || string(reply.Parameters["value"]) != "false" {
		t.Fatal("CLI command did not reach the device")
	}
}

func testTransportPersistenceRollback(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef" // gitleaks:allow
	const id network.DeviceID = "02:00:00:00:00:64"
	directory := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(directory, "devices.json")
	baseline := typedSeedBaseline(t, network.FamilySwitch, "original")
	writeTypedJSON(t, state, []controller.Device{{MAC: string(id), Key: key, Baseline: baseline, DesiredVersion: "original"}})
	c := openTypedController(t, state)
	client := network.Dial(startTypedSocket(t, c))
	report := informmodel.Report{Type: "usw", PortTable: []informmodel.Port{{Index: 1, Interface: "eth0"}}}
	typedExchange(t, c, id, key, report, false)
	if err := client.SendCommand(t.Context(), id, network.Command{Name: "pending"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(state); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(directory); err != nil {
		t.Fatal(err)
	}
	writeTypedFixture(t, directory, []byte("blocked directory"))
	replacement := network.Config{Version: "replacement", Management: "a=b\n", System: "c=d\n"}
	_, err := client.ApplyConfig(t.Context(), id, replacement)
	assertControlFailure(t, err, network.PersistenceFailed, "")
	err = client.ImportBaseline(t.Context(), id, network.BaselineImport{Config: replacement})
	assertControlFailure(t, err, network.PersistenceFailed, "")
	if c.Status()[0].Pending != 1 || c.Status()[0].DesiredConfigVersion != "original" {
		t.Fatal("failed transaction changed the prior queue or version")
	}
	if err := os.Remove(directory); err != nil {
		t.Fatal(err)
	}
	if err := c.Register(string(id), key); err != nil {
		t.Fatal(err)
	}
	device := readTransportDevice(t, state)
	if device.Baseline.Config != baseline.Config || device.LastSetParam != nil || device.DesiredVersion != "original" {
		t.Fatal("failed transaction changed in-memory baseline")
	}
	if reply := typedExchange(t, c, id, key, report, true); string(reply.Command) != "pending" {
		t.Fatal("failed transaction replaced queued command")
	}
}
