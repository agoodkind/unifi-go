package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jamesbraid/unifi-emu/inform"
	"goodkind.io/unifi-go/internal/configmap"
	"goodkind.io/unifi-go/internal/controller"
	"goodkind.io/unifi-go/internal/informmodel"
	"goodkind.io/unifi-go/internal/profile"
	"goodkind.io/unifi-go/internal/profile/ap"
	"goodkind.io/unifi-go/internal/profile/switches"
	"goodkind.io/unifi-go/network"
)

func TestTypedCLIRejectsUnknownNestedPolicy(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "nested-unknown.json")
	writeTypedFixture(t, configPath, []byte(`{"radios":[{"band":"2.4ghz","power":{"mode":"auto","mod":"typo"}}]}`))

	var output bytes.Buffer
	err := run(t.Context(), []string{"apply", "ap", "--device", "02:00:00:00:00:11", "--file", configPath, "--socket", filepath.Join(directory, "missing.sock")}, &output)
	if err == nil || err.Error() != "invalid typed configuration or unknown field" {
		t.Fatalf("run() error = %v", err)
	}
}

func TestPersistedBaselineRejectsIncompleteResourceIdentity(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef" // gitleaks:allow
	const version network.ConfigVersion = "review-v1"
	management := "cfgversion=" + string(version) + "\n"
	switchConfig := typedSwitchFixture()
	apConfig := typedAPFixture("/run/secrets/review")
	tests := map[string]controller.Device{
		"switch unknown port field": {
			MAC: "02:00:00:00:00:31", Key: key, Family: network.FamilySwitch,
			Descriptor:     &profile.DeviceDescriptor{Family: network.FamilySwitch, Ports: []profile.PortCapability{{Index: 1, Interface: "eth0"}}},
			DesiredSwitch:  &switchConfig,
			DesiredVersion: version,
			LastSetParam: &controller.Reply{
				Type: controller.ReplySetparam, ConfigVersion: string(version), ManagementConfig: management,
				SystemConfig: "switch.port.1.unknown=value\n",
			},
		},
		"access point missing devnames": {
			MAC: "02:00:00:00:00:32", Key: key, Family: network.FamilyAP,
			Descriptor:     &profile.DeviceDescriptor{Family: network.FamilyAP, Radios: []profile.RadioCapability{{ID: "ng", Interface: "wifi0", Band: network.Band2GHz}}},
			DesiredAP:      &apConfig,
			DesiredVersion: version,
			LastSetParam: &controller.Reply{
				Type: controller.ReplySetparam, ConfigVersion: string(version), ManagementConfig: management,
				SystemConfig: "radio.1.phyname=wifi0\nwireless.1.ssid=Documentation\nwireless.1.parent=wifi0\naaa.1.ssid=Documentation\n",
			},
		},
	}

	for name, device := range tests {
		t.Run(name, func(t *testing.T) {
			state := filepath.Join(t.TempDir(), "state.json")
			writeTypedJSON(t, state, []controller.Device{device})
			c := openTypedController(t, state)
			if err := c.Register(device.MAC, key); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(state)
			if err != nil {
				t.Fatal(err)
			}
			var persisted []controller.Device
			if err := json.Unmarshal(data, &persisted); err != nil {
				t.Fatal(err)
			}
			if len(persisted) != 1 || persisted[0].Baseline == nil || persisted[0].Baseline.TypedReady {
				t.Fatal("incomplete resource identity marked typed ready")
			}
		})
	}
}

func TestTypedControlIntegration(t *testing.T) {
	t.Run("preview transaction", testPreviewTransaction)
	var omitted network.Optional[bool]
	disabled := network.Supplied(false)
	untagged := network.Cleared[network.VLANID]()
	if omitted.Present || !disabled.Present || disabled.Value || !untagged.Null {
		t.Fatal("policy presence changed")
	}
	presenceJSON, err := json.Marshal(struct {
		Omitted  network.Optional[network.PoEMode] `json:"omitted,omitzero"`
		Disabled network.Optional[bool]            `json:"disabled,omitzero"`
		Untagged network.Optional[network.VLANID]  `json:"untagged,omitzero"`
	}{Omitted: network.Optional[network.PoEMode]{}, Disabled: disabled, Untagged: untagged})
	if err != nil || string(presenceJSON) != `{"disabled":false,"untagged":null}` {
		t.Fatal("policy presence JSON shape changed")
	}
	var malformedPresence network.Optional[bool]
	if err := json.Unmarshal([]byte("false true"), &malformedPresence); err == nil {
		t.Fatal("trailing policy JSON was accepted")
	}

	ctx := context.Background()
	directory := t.TempDir()
	state := filepath.Join(directory, "state.json")
	const key = "0123456789abcdef0123456789abcdef"
	const apID network.DeviceID = "02:00:00:00:00:11"
	const switchID network.DeviceID = "02:00:00:00:00:12"
	const secret = "documentation-only-password"
	const storedHash = "$6$synthetic$persisted-prehashed-marker"
	const storedPlaintext = "unused-persisted-plaintext-marker"
	secretPath := filepath.Join(directory, "credential")
	writeTypedFixture(t, secretPath, []byte(secret))
	// This is the legacy persisted shape, before typed fields existed.
	legacy := []struct {
		MAC             network.DeviceID                  `json:"mac"`
		Key             string                            `json:"key"`
		SSHUsername     string                            `json:"ssh_username,omitempty"`
		SSHPassword     string                            `json:"ssh_password,omitempty"`
		SSHPasswordHash string                            `json:"ssh_password_hash,omitempty"`
		Baseline        *controller.ConfigurationBaseline `json:"baseline,omitempty"`
	}{{MAC: apID, Key: key, SSHUsername: "preserved-user", SSHPassword: storedPlaintext, SSHPasswordHash: storedHash}, {MAC: switchID, Key: key, SSHUsername: "", SSHPassword: "", SSHPasswordHash: ""}}
	legacy[0].Baseline = typedSeedBaseline(t, network.FamilyAP, "seed")
	legacy[1].Baseline = typedSeedBaseline(t, network.FamilySwitch, "seed")
	legacy[0].Baseline.Config.System += "sshd.status=enabled\nsshd.1.ifname=br0\nusers.1.name=preserved-user\nusers.1.password=" + storedHash + "\n"
	writeTypedJSON(t, state, legacy)
	c := openTypedController(t, state)
	socket := startTypedSocket(t, c)
	client := network.Dial(socket)
	apConfig := typedAPFixture(secretPath)
	swConfig := typedSwitchFixture()
	_, err = client.ApplyAP(ctx, apID, apConfig)
	assertControlFailure(t, err, network.NoReport, "")
	up := true
	poe := uint64(1)
	apReport := informmodel.Report{Model: "DocumentationAP", Version: "1", RadioTable: []informmodel.Radio{{Name: "wifi0", Radio: "ng"}}, PortTable: []informmodel.Port{{Index: 1, Interface: "eth0"}}, VAPTable: []informmodel.VAP{{Name: "ath0", Radio: "ng", ESSID: "Documentation", Stations: []informmodel.Station{{MAC: "02:00:00:00:00:21", IP: "192.0.2.21"}}}}}
	apReport.LastError = secret
	apReport.RadioTable[0].Widths = []informmodel.Uint16Scalar{20}
	swReport := informmodel.Report{Type: "usw", Model: "DocumentationSwitch", Version: "1", PortTable: []informmodel.Port{{Index: 1, Interface: "eth0", Up: &up, PoECaps: &poe}}}
	swReport.SwitchCaps = &informmodel.SwitchCapabilities{VLANCaps: &poe}
	typedExchange(t, c, apID, key, apReport, false)
	typedExchange(t, c, switchID, key, swReport, true)
	invalid := apConfig
	invalid.Networks.Value = []network.WiFiNetwork{apConfig.Networks.Value[0]}
	invalid.Networks.Value[0].Bands = network.Supplied([]network.RadioBand{})
	_, err = client.ApplyAP(ctx, apID, invalid)
	assertControlFailure(t, err, network.InvalidConfig, "networks[0].bands")
	invalid = apConfig
	power := 10
	invalid.Radios.Value = []network.RadioConfig{apConfig.Radios.Value[0]}
	invalid.Radios.Value[0].Power.Value.DBm = network.Supplied(power)
	if _, err := client.ApplyAP(ctx, apID, invalid); err == nil {
		t.Fatal("automatic explicit power accepted")
	}
	invalid = apConfig
	invalid.SSH = network.Supplied(network.SSHConfig{Username: network.Supplied("")}) // gitleaks:allow
	if _, err := client.ApplyAP(ctx, apID, invalid); err == nil {
		t.Fatal("invalid SSH accepted")
	}
	apVersion, err := client.ApplyAP(ctx, apID, apConfig)
	if err != nil {
		t.Fatal(err)
	}
	swVersion, err := client.ApplySwitch(ctx, switchID, swConfig)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ApplyAP(ctx, switchID, apConfig)
	assertControlFailure(t, err, network.FamilyMismatch, "")
	if _, err := client.ApplySwitch(ctx, apID, swConfig); err == nil {
		t.Fatal("switch applied to AP")
	}
	var firstSystem configmap.Values
	for _, entry := range []struct {
		id      network.DeviceID
		report  informmodel.Report
		version network.ConfigVersion
		gcm     bool
	}{{apID, apReport, apVersion, false}, {switchID, swReport, swVersion, true}} {
		reply := typedExchange(t, c, entry.id, key, entry.report, entry.gcm)
		if reply.Type != controller.ReplySetparam || reply.ConfigVersion != string(entry.version) {
			t.Fatal("desired reply missing")
		}
		management, err := configmap.Parse(reply.ManagementConfig)
		if err != nil {
			t.Fatal(err)
		}
		if management["authkey"] != key || management["inform_url"] != "http://192.0.2.1:8080/inform" || management["cfgversion"] != string(entry.version) {
			t.Fatal("management ownership missing")
		}
		system := assertTypedMetadata(t, reply, key)
		if entry.id == apID {
			firstSystem = system
			if system["users.1.password"] != storedHash || system["users.1.name"] != "preserved-user" || system["sshd.1.ifname"] != "br0" || strings.Contains(reply.SystemConfig, storedPlaintext) {
				t.Fatal("stored SSH access was not preserved")
			}
		} else {
			for name := range system {
				if strings.HasPrefix(name, "sshd.") || strings.HasPrefix(name, "users.") {
					t.Fatal("typed apply generated SSH credentials")
				}
			}
		}
		if entry.id == apID && !strings.Contains(reply.SystemConfig, secret) {
			t.Fatal("AP secret was not compiled")
		}
		if entry.id == switchID && !strings.Contains(reply.SystemConfig, "vlan.") {
			t.Fatal("switch VLAN configuration missing")
		}
		entry.report.ConfigVersion = string(entry.version)
		typedExchange(t, c, entry.id, key, entry.report, entry.gcm)
	}
	apReport.ConfigVersion, swReport.ConfigVersion = string(apVersion), string(swVersion)
	snapshots, err := client.Devices(ctx)
	if err != nil || len(snapshots) != 2 || snapshots[0].ID != apID {
		t.Fatal("device list failed")
	}
	snapshot, err := client.Device(ctx, apID)
	if err != nil || snapshot.AP == nil || snapshot.Switch != nil || snapshot.LastInform.IsZero() || len(snapshot.AP.Clients) != 1 {
		t.Fatal("AP observation missing")
	}
	switchSnapshot, err := client.Device(ctx, switchID)
	if err != nil || switchSnapshot.Switch == nil || switchSnapshot.AP != nil || switchSnapshot.Switch.Ports[0].NativeVLAN != nil {
		t.Fatal("switch observation incorrectly echoes desired state")
	}
	if snapshot.LastError != "device reported an error" {
		t.Fatal("typed error presence missing")
	}
	for _, status := range c.Status() {
		if status.LastError == secret {
			t.Fatal("legacy status retained raw error")
		}
	}
	for _, arguments := range [][]string{{"status"}, {"devices"}, {"device", "--device", string(apID)}, {"clients", "--device", string(apID)}, {"ports", "--device", string(switchID)}} {
		var output bytes.Buffer
		if err := run(ctx, append(arguments, "--socket", socket), &output); err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{secret, secretPath, key, storedHash, storedPlaintext, "desired_ap", "ssh_password"} {
			if strings.Contains(output.String(), forbidden) {
				t.Fatal("CLI exposed secret material")
			}
		}
	}
	unknown := filepath.Join(directory, "unknown.json")
	writeTypedFixture(t, unknown, []byte(`{"country_code":840,"unknown":"documentation-only-password"}`))
	var output bytes.Buffer
	if err := run(ctx, []string{"apply", "ap", "--device", string(apID), "--file", unknown, "--socket", socket}, &output); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("unknown field was accepted or leaked")
	}
	invalidFile := filepath.Join(directory, "invalid.json")
	writeTypedJSON(t, invalidFile, invalid)
	err = run(ctx, []string{"apply", "ap", "--device", string(apID), "--file", invalidFile, "--socket", socket}, &output)
	assertControlFailure(t, err, network.InvalidConfig, "ssh.username")
	missing := apConfig
	missing.Networks.Value = []network.WiFiNetwork{apConfig.Networks.Value[0]}
	missing.Networks.Value[0].Security.Value.PSK = network.Supplied(network.SecretFile(filepath.Join(directory, "missing-secret")))
	_, err = client.ApplyAP(ctx, apID, missing)
	assertControlFailure(t, err, network.FileReadFailed, "networks")
	oversized := filepath.Join(directory, "oversized.json")
	writeTypedFixture(t, oversized, append(append([]byte("{}"), bytes.Repeat([]byte(" "), 8388608)...), []byte("{}")...))
	if err := run(ctx, []string{"apply", "switch", "--device", string(switchID), "--file", oversized, "--socket", socket}, &output); err == nil || !strings.Contains(err.Error(), "exceeds 8 MiB") {
		t.Fatal("oversized config accepted")
	}
	binaryPath := filepath.Join(directory, "unifi-go")
	if err := os.Remove(binaryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	buildStarted := time.Now()
	if output, err := exec.CommandContext(ctx, "go", "build", "-o", binaryPath, ".").CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v: %s", err, output)
	}
	binaryInfo, err := os.Stat(binaryPath)
	if err != nil || binaryInfo.ModTime().Before(buildStarted) {
		t.Fatal("CLI build did not produce a fresh executable")
	}
	processOutput, processErr := exec.CommandContext(ctx, binaryPath, "apply", "ap", "--device", string(apID), "--file", invalidFile, "--socket", socket).CombinedOutput()
	exitError, ok := errors.AsType[*exec.ExitError](processErr)
	if !ok || exitError.ExitCode() != 1 || !bytes.Contains(processOutput, []byte("invalid_config: ssh.username")) {
		t.Fatal("executable did not return actionable failure with exit 1")
	}
	if bytes.Contains(processOutput, []byte(secret)) || bytes.Contains(processOutput, []byte(secretPath)) {
		t.Fatal("executable leaked credential")
	}
	for _, family := range []string{"ap", "switch"} {
		configFile := filepath.Join(directory, family+".json")
		id := apID
		if family == "ap" {
			writeTypedJSON(t, configFile, apConfig)
		} else {
			id = switchID
			writeTypedJSON(t, configFile, swConfig)
		}
		previewConfigFile := filepath.Join(directory, family+"-preview.json")
		if family == "ap" {
			previewConfig := apConfig
			previewConfig.Networks.Value = append([]network.WiFiNetwork(nil), apConfig.Networks.Value...)
			previewConfig.Networks.Value[0].BSSTransition = network.Supplied(network.BSSTransitionDisabled)
			writeTypedJSON(t, previewConfigFile, previewConfig)
		} else {
			previewConfig := swConfig
			previewConfig.Ports.Value = append([]network.SwitchPortConfig(nil), swConfig.Ports.Value...)
			previewConfig.Ports.Value[0].Enabled = network.Supplied(true)
			writeTypedJSON(t, previewConfigFile, previewConfig)
		}
		beforePreview := previewStateBytes(t, state)
		previewOutput, err := exec.CommandContext(ctx, binaryPath, "apply", family, "--device", string(id), "--file", previewConfigFile, "--socket", socket, "--dry-run").CombinedOutput()
		if err != nil {
			t.Fatal("fresh executable preview failed")
		}
		var preview network.ConfigPreview
		decoder := json.NewDecoder(bytes.NewReader(previewOutput))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&preview); err != nil || preview.Token == "" || decoder.Decode(new(json.RawMessage)) != io.EOF {
			t.Fatal("fresh executable did not return only ConfigPreview")
		}
		if !bytes.Equal(beforePreview, previewStateBytes(t, state)) {
			t.Fatal("fresh executable preview changed state")
		}
		for _, status := range c.Status() {
			if status.Pending != 0 {
				t.Fatal("fresh executable preview queued work")
			}
		}
		tokenFile := filepath.Join(directory, family+".token")
		writeTypedFixture(t, tokenFile, []byte(string(preview.Token)+"\n"))
		beforeTokenApply := previewStateBytes(t, state)
		tokenApplyOutput, err := exec.CommandContext(ctx, binaryPath, "apply", family, "--device", string(id), "--file", previewConfigFile, "--socket", socket, "--preview-token-file", tokenFile).CombinedOutput()
		if err != nil {
			t.Fatal("fresh executable token application failed")
		}
		if bytes.Equal(beforeTokenApply, previewStateBytes(t, state)) {
			t.Fatal("token application did not persist a state change")
		}
		for _, forbidden := range []string{secret, secretPath, key, storedHash, storedPlaintext, "desired_ap", "ssh_password"} {
			if strings.Contains(string(tokenApplyOutput), forbidden) {
				t.Fatal("token application output exposed credentials")
			}
		}
		var previewVersion struct {
			Version network.ConfigVersion `json:"version"`
		}
		if err := json.Unmarshal(tokenApplyOutput, &previewVersion); err != nil || previewVersion.Version == "" {
			t.Fatal("token application did not return a version")
		}
		if family == "ap" {
			apReport.ConfigVersion = string(previewVersion.Version)
			reply := typedExchange(t, c, apID, key, apReport, false)
			if reply.ConfigVersion != string(previewVersion.Version) {
				t.Fatal("preview token configuration was not delivered")
			}
			restoredVersion, err := client.ApplyAP(ctx, apID, apConfig)
			if err != nil {
				t.Fatal(err)
			}
			apReport.ConfigVersion = string(restoredVersion)
			if reply := typedExchange(t, c, apID, key, apReport, false); reply.ConfigVersion != string(restoredVersion) {
				t.Fatal("original AP configuration was not restored")
			}
		} else {
			swReport.ConfigVersion = string(previewVersion.Version)
			reply := typedExchange(t, c, switchID, key, swReport, true)
			if reply.ConfigVersion != string(previewVersion.Version) {
				t.Fatal("preview token configuration was not delivered")
			}
			restoredVersion, err := client.ApplySwitch(ctx, switchID, swConfig)
			if err != nil {
				t.Fatal(err)
			}
			swReport.ConfigVersion = string(restoredVersion)
			if reply := typedExchange(t, c, switchID, key, swReport, true); reply.ConfigVersion != string(restoredVersion) {
				t.Fatal("original switch configuration was not restored")
			}
		}
		output.Reset()
		if err := run(ctx, []string{"apply", family, "--device", string(id), "--file", configFile, "--socket", socket}, &output); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output.String(), secret) || strings.Contains(output.String(), secretPath) {
			t.Fatal("apply output exposed credentials")
		}
		if _, err := exec.CommandContext(ctx, binaryPath, "apply", family, "--device", string(id), "--file", configFile, "--socket", socket, "--dry-run", "--preview-token-file", tokenFile).CombinedOutput(); err == nil {
			t.Fatal("fresh executable accepted conflicting preview flags")
		}
	}
	if _, err := client.ApplyAP(ctx, apID, apConfig); err != nil {
		t.Fatal(err)
	}
	if reply := typedExchange(t, c, apID, key, apReport, false); reply.Type != controller.ReplyNoop {
		t.Fatal("unchanged configuration was queued")
	}
	repeated := assertTypedMetadata(t, typedPersistedReply(t, state, apID), key)
	assertSameTypedIdentity(t, firstSystem, repeated)
	if _, err := client.ApplySwitch(ctx, switchID, swConfig); err != nil {
		t.Fatal(err)
	}
	reloaded := openTypedController(t, state)
	restarted := network.Dial(startTypedSocket(t, reloaded))
	snapshot, err = restarted.Device(ctx, apID)
	if err != nil || snapshot.AP == nil || !snapshot.LastInform.IsZero() || len(snapshot.AP.Clients) != 0 {
		t.Fatal("observations survived restart")
	}
	persisted, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	var records []controller.Device
	if err := json.Unmarshal(persisted, &records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Key != key || records[0].DesiredAP == nil || records[0].DesiredVersion != apVersion || records[1].DesiredSwitch == nil || records[1].DesiredVersion != swVersion || records[0].LastSetParam == nil || records[0].LastSetParam.ConfigVersion != string(apVersion) || records[1].LastSetParam == nil || records[1].LastSetParam.ConfigVersion != string(swVersion) || records[0].Baseline == nil || !records[0].Baseline.TypedReady || records[1].Baseline == nil || !records[1].Baseline.TypedReady {
		t.Fatal("desired state or keys did not survive")
	}
	persistedAP := records[0].DesiredAP
	persistedSwitch := records[1].DesiredSwitch
	if persistedAP.SSH.Present || !persistedAP.Networks.Value[0].VLAN.Present || !persistedAP.Networks.Value[0].VLAN.Null {
		t.Fatal("absent and explicitly cleared policy did not survive")
	}
	if !persistedSwitch.Ports.Value[0].Enabled.Present || persistedSwitch.Ports.Value[0].Enabled.Value {
		t.Fatal("explicit false policy did not survive")
	}
	permissions, err := os.Stat(state)
	if err != nil || permissions.Mode().Perm() != 0o600 {
		t.Fatal("state permissions incorrect")
	}
	for _, entry := range []struct {
		id     network.DeviceID
		report informmodel.Report
	}{{apID, apReport}, {switchID, swReport}} {
		if reply := typedExchange(t, reloaded, entry.id, key, entry.report, true); reply.Type != controller.ReplyNoop {
			t.Fatal("pending command survived restart")
		}
	}
	snapshot, err = restarted.Device(ctx, apID)
	if err != nil || snapshot.LastInform.IsZero() || len(snapshot.AP.Clients) != 1 {
		t.Fatal("fresh inform did not restore observations")
	}
	restartedVersion, err := restarted.ApplyAP(ctx, apID, apConfig)
	if err != nil || restartedVersion != apVersion {
		t.Fatal("restarted Apply changed the desired version")
	}
	if reply := typedExchange(t, reloaded, apID, key, apReport, true); reply.Type != controller.ReplyNoop {
		t.Fatal("unchanged restarted configuration was queued")
	}
	restartedSystem := assertTypedMetadata(t, typedPersistedReply(t, state, apID), key)
	assertSameTypedIdentity(t, firstSystem, restartedSystem)
	if restartedSystem["users.1.password"] != storedHash {
		t.Fatal("restart lost the persisted SSH hash")
	}
	uplinkReport := apReport
	uplinkReport.Uplink = &informmodel.UplinkValue{Uplink: informmodel.Uplink{Interface: "eth1"}, Interface: "eth1"}
	typedExchange(t, reloaded, apID, key, uplinkReport, true)
	if _, err := restarted.ApplyAP(ctx, apID, apConfig); err != nil {
		t.Fatal(err)
	}
	if reply := typedExchange(t, reloaded, apID, key, uplinkReport, true); reply.Type != controller.ReplyNoop {
		t.Fatal("unrelated uplink report queued unchanged policy")
	}
	uplinkSystem := assertTypedMetadata(t, typedPersistedReply(t, state, apID), key)
	if uplinkSystem["sshd.1.ifname"] != "br0" {
		t.Fatal("preserved AP SSH did not bind the management bridge")
	}
	explicitSSH := apConfig
	explicitSSH.SSH = network.Supplied(network.SSHConfig{Username: network.Supplied("explicit-user"), Password: network.Supplied(network.SecretFile(secretPath))}) // gitleaks:allow
	if _, err := restarted.ApplyAP(ctx, apID, explicitSSH); err != nil {
		t.Fatal(err)
	}
	explicitReply := typedExchange(t, reloaded, apID, key, apReport, true)
	explicitSystem := assertTypedMetadata(t, explicitReply, key)
	apReport.ConfigVersion = explicitReply.ConfigVersion
	typedExchange(t, reloaded, apID, key, apReport, true)
	if explicitSystem["users.1.name"] != "explicit-user" || explicitSystem["users.1.password"] == storedHash || explicitSystem["users.1.password"] == secret || !strings.HasPrefix(explicitSystem["users.1.password"], "$6$") {
		t.Fatal("stored SSH overrode explicit typed SSH")
	}
	if _, err := restarted.ApplyAP(ctx, apID, apConfig); err != nil {
		t.Fatal(err)
	}
	if reply := typedExchange(t, reloaded, apID, key, apReport, true); reply.Type != controller.ReplyNoop {
		t.Fatal("omitted SSH policy queued unchanged configuration")
	}
	omittedSystem := assertTypedMetadata(t, typedPersistedReply(t, state, apID), key)
	if omittedSystem["users.1.name"] != "explicit-user" || omittedSystem["users.1.password"] != explicitSystem["users.1.password"] {
		t.Fatal("omitted SSH restored obsolete adoption credentials")
	}
	latest, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	var latestRecords []controller.Device
	if err := json.Unmarshal(latest, &latestRecords); err != nil {
		t.Fatal(err)
	}
	if latestRecords[0].SSHPassword != "" || latestRecords[0].SSHPasswordHash != explicitSystem["users.1.password"] || latestRecords[0].SSHUsername != "explicit-user" {
		t.Fatal("effective SSH credentials were not persisted without obsolete plaintext")
	}
	afterSSHRestart := openTypedController(t, state)
	afterSSHClient := network.Dial(startTypedSocket(t, afterSSHRestart))
	typedExchange(t, afterSSHRestart, apID, key, apReport, true)
	if _, err := afterSSHClient.ApplyAP(ctx, apID, apConfig); err != nil {
		t.Fatal(err)
	}
	if reply := typedExchange(t, afterSSHRestart, apID, key, apReport, true); reply.Type != controller.ReplyNoop {
		t.Fatal("unchanged SSH policy queued after restart")
	}
	afterSSHSystem := assertTypedMetadata(t, typedPersistedReply(t, state, apID), key)
	if afterSSHSystem["users.1.password"] != explicitSystem["users.1.password"] || afterSSHSystem["users.1.name"] != "explicit-user" {
		t.Fatal("restart restored obsolete SSH credentials")
	}
	switchState := filepath.Join(directory, "stored-switch-ssh.json")
	switchRecord := records[1]
	switchRecord.SSHUsername, switchRecord.SSHPasswordHash = "preserved-user", storedHash
	switchRecord.Baseline.Config.System += "sshd.status=enabled\nsshd.1.ifname=eth0\nusers.1.name=preserved-user\nusers.1.password=" + storedHash + "\n"
	writeTypedJSON(t, switchState, []controller.Device{switchRecord})
	switchController := openTypedController(t, switchState)
	switchClient := network.Dial(startTypedSocket(t, switchController))
	switchReport := swReport
	switchReport.PortTable = append([]informmodel.Port{{Index: 2, Interface: "eth1"}}, swReport.PortTable...)
	switchReport.Uplink = uplinkReport.Uplink
	typedExchange(t, switchController, switchID, key, switchReport, true)
	if _, err := switchClient.ApplySwitch(ctx, switchID, swConfig); err != nil {
		t.Fatal(err)
	}
	switchSystem := assertTypedMetadata(t, typedExchange(t, switchController, switchID, key, switchReport, true), key)
	if switchSystem["sshd.1.ifname"] != "eth0" || switchSystem["users.1.password"] != storedHash {
		t.Fatal("preserved switch SSH did not select the lowest-index interface")
	}
	badState := filepath.Join(directory, "invalid-stored-ssh.json")
	records[0].SSHPasswordHash = storedHash + "\ninjected=value"
	writeTypedJSON(t, badState, records)
	badController := openTypedController(t, badState)
	badClient := network.Dial(startTypedSocket(t, badController))
	badReport := apReport
	badReport.ConfigVersion = string(records[0].DesiredVersion)
	typedExchange(t, badController, apID, key, badReport, true)
	_, err = badClient.ApplyAP(ctx, apID, apConfig)
	if err != nil {
		t.Fatal("unrelated legacy credential metadata overrode the baseline")
	}
	if reply := typedExchange(t, badController, apID, key, badReport, true); reply.Type != controller.ReplyNoop {
		t.Fatal("legacy credential metadata changed baseline policy")
	}
	if strings.Contains(typedPersistedReply(t, badState, apID).SystemConfig, "injected=value") {
		t.Fatal("legacy credential metadata changed persisted policy")
	}
	const pendingID network.DeviceID = "02:00:00:00:00:13"
	if err := reloaded.Adopt(string(pendingID), controller.Reply{Type: controller.ReplySetparam, ManagementConfig: "cfgversion=adopt\n", SystemConfig: "users.status=enabled\n"}, false); err != nil {
		t.Fatal(err)
	}
	_, err = restarted.ApplyAP(ctx, pendingID, apConfig)
	assertControlFailure(t, err, network.AdoptionPending, "")

	legacyPresenceState := filepath.Join(directory, "legacy-presence.json")
	const legacyManagement = "cfgversion=legacy-presence\nunknown.management=exact value \n"
	const legacySystem = "aaa.1.bss_transition=disabled\nunknown.system=exact value \n"
	legacyPresenceJSON := strings.Replace(`[{"mac":"02:00:00:00:00:14","key":"fixture-key","desired_ap":{"country_code":840,"networks":[{"name":"Legacy","enabled":false,"vlan":null,"bands":[],"security":{"mode":"wpa2-personal","psk":"/legacy-secret"}}],"radios":[]},"desired_version":"legacy-presence","last_setparam":{"_type":"setparam","cfgversion":"legacy-presence","mgmt_cfg":"cfgversion=legacy-presence\nunknown.management=exact value \n","system_cfg":"aaa.1.bss_transition=disabled\nunknown.system=exact value \n"}}]`, "fixture-key", key, 1)
	writeTypedFixture(t, legacyPresenceState, []byte(legacyPresenceJSON))
	legacyController := openTypedController(t, legacyPresenceState)
	legacyClient := network.Dial(startTypedSocket(t, legacyController))
	if _, err := legacyClient.Device(ctx, "02:00:00:00:00:14"); err != nil {
		t.Fatal(err)
	}
	if reply := typedExchange(t, legacyController, "02:00:00:00:00:14", key, informmodel.Report{Model: "LegacyPresence", Version: "1"}, false); reply.Type != controller.ReplyNoop {
		t.Fatal("baseline migration replayed configuration")
	}
	if err := legacyController.Register("02:00:00:00:00:14", key); err != nil {
		t.Fatal(err)
	}
	legacyPersisted, err := os.ReadFile(legacyPresenceState)
	if err != nil {
		t.Fatal(err)
	}
	var migrated []controller.Device
	if err := json.Unmarshal(legacyPersisted, &migrated); err != nil {
		t.Fatal(err)
	}
	if len(migrated) != 1 || migrated[0].DesiredAP == nil || migrated[0].DesiredAP.Networks.Value[0].BSSTransition.Present {
		t.Fatal("legacy omitted enum became supplied")
	}
	if migrated[0].LastSetParam == nil || migrated[0].LastSetParam.ManagementConfig != legacyManagement || migrated[0].LastSetParam.SystemConfig != legacySystem || migrated[0].Baseline == nil || migrated[0].Baseline.Config.Management != legacyManagement || migrated[0].Baseline.Config.System != legacySystem || migrated[0].Baseline.TypedReady {
		t.Fatal("legacy baseline migration changed exact bodies or claimed typed ownership")
	}
	testTypedBSSPersistence(t, ctx, directory, key, secretPath)
}

func typedAPFixture(secretPath string) network.APConfig {
	return network.APConfig{
		CountryCode: network.Supplied(uint16(840)),
		Radios: network.Supplied([]network.RadioConfig{{
			Band: network.Band2GHz, Enabled: network.Supplied(true), Channel: network.Cleared[uint16](),
			WidthMHz: network.Supplied(network.Width20),
			Power:    network.Supplied(network.PowerConfig{Mode: network.Supplied(network.PowerAuto)}),
		}}),
		Networks: network.Supplied([]network.WiFiNetwork{{
			Name: "Documentation", Enabled: network.Supplied(true), VLAN: network.Cleared[network.VLANID](),
			Bands:         network.Supplied([]network.RadioBand{network.Band2GHz}),
			BSSTransition: network.Supplied(network.BSSTransitionEnabled),
			Security: network.Supplied(network.WiFiSecurity{
				Mode: network.Supplied(network.WPA2Personal), PSK: network.Supplied(network.SecretFile(secretPath)),
			}),
		}}),
	}
}

func typedSwitchFixture() network.SwitchConfig {
	return network.SwitchConfig{Ports: network.Supplied([]network.SwitchPortConfig{{
		Index: 1, Enabled: network.Supplied(false), NativeVLAN: network.Supplied(network.VLANID(20)),
		TaggedVLANs: network.Supplied([]network.VLANID{30}), PoE: network.Supplied(network.PoEAuto),
	}})}
}

func TestConfigVersionUXIntegration(t *testing.T) {
	directory := t.TempDir()
	state := filepath.Join(directory, "state.json")
	const key = "0123456789abcdef0123456789abcdef"
	const id network.DeviceID = "02:00:00:00:00:41"
	legacySetParam := controller.Reply{Type: controller.ReplySetparam, ConfigVersion: "legacy-v0", ManagementConfig: "cfgversion=legacy-v0\n"}
	legacy := []struct {
		MAC      network.DeviceID                  `json:"mac"`
		Key      string                            `json:"key"`
		Config   controller.Reply                  `json:"config"`
		Baseline *controller.ConfigurationBaseline `json:"baseline,omitempty"`
	}{{MAC: id, Key: key, Config: legacySetParam, Baseline: typedSeedBaseline(t, network.FamilyAP, "legacy-v0")}}
	writeTypedJSON(t, state, legacy)

	controllerInstance := openTypedController(t, state)
	client := network.Dial(startTypedSocket(t, controllerInstance))
	report := informmodel.Report{
		Type:          "uap",
		ConfigVersion: "reported-v1",
		Model:         "VersionAP",
		Version:       "1",
		RadioTable:    []informmodel.Radio{{Name: "wifi0", Radio: "ng", Widths: []informmodel.Uint16Scalar{20}}},
		PortTable:     []informmodel.Port{{Index: 1, Interface: "eth0"}},
	}
	typedExchange(t, controllerInstance, id, key, report, false)
	assertVersionState(t, client, id, "reported-v1", "", "legacy-v0")

	typedConfig := network.APConfig{
		CountryCode: network.Supplied(uint16(840)),
		Networks:    network.Supplied([]network.WiFiNetwork{}),
		Radios: network.Supplied([]network.RadioConfig{{
			Band: network.Band2GHz, Enabled: network.Supplied(true), Channel: network.Cleared[uint16](),
			WidthMHz: network.Supplied(network.Width20),
			Power:    network.Supplied(network.PowerConfig{Mode: network.Supplied(network.PowerAuto)}),
		}}),
	}
	typedVersion, err := client.ApplyAP(t.Context(), id, typedConfig)
	if err != nil {
		t.Fatal(err)
	}
	assertVersionState(t, client, id, "reported-v1", typedVersion, typedVersion)
	if reply := typedExchange(t, controllerInstance, id, key, report, false); reply.ConfigVersion != string(typedVersion) {
		t.Fatal("typed setparam was not delivered")
	}
	report.ConfigVersion = string(typedVersion)
	typedExchange(t, controllerInstance, id, key, report, false)
	assertVersionState(t, client, id, typedVersion, typedVersion, typedVersion)

	rawConfig := network.Config{Version: "raw-v2", Management: "cfgversion=raw-v2\n"}
	if _, err := client.ApplyConfig(t.Context(), id, rawConfig); err != nil {
		t.Fatal(err)
	}
	assertVersionState(t, client, id, typedVersion, "", rawConfig.Version)
	if reply := typedExchange(t, controllerInstance, id, key, report, false); reply.ConfigVersion != string(rawConfig.Version) {
		t.Fatal("raw setparam was not delivered")
	}
	report.ConfigVersion = string(rawConfig.Version)
	typedExchange(t, controllerInstance, id, key, report, false)
	assertVersionState(t, client, id, rawConfig.Version, "", rawConfig.Version)

	persisted, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	var records []map[string]json.RawMessage
	if err := json.Unmarshal(persisted, &records); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0]["last_setparam"] == nil || records[0]["config"] != nil {
		t.Fatal("legacy config field was not migrated")
	}
	var devices []controller.Device
	if err := json.Unmarshal(persisted, &devices); err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].Baseline == nil || devices[0].Baseline.TypedReady || devices[0].Baseline.Config != rawConfig || devices[0].DesiredAP != nil || devices[0].DesiredVersion != "" {
		t.Fatal("later raw configuration retained stale typed ownership")
	}

	malformedState := filepath.Join(t.TempDir(), "devices.json")
	duplicateBody := "cfgversion=duplicate\ncfgversion=duplicate-again\n"
	malformedLegacy := []controller.Device{{
		MAC: string(id), Key: key,
		LastSetParam: &controller.Reply{Type: controller.ReplySetparam, ConfigVersion: "duplicate", ManagementConfig: duplicateBody},
	}}
	writeTypedJSON(t, malformedState, malformedLegacy)
	malformedController := openTypedController(t, malformedState)
	malformedClient := network.Dial(startTypedSocket(t, malformedController))
	assertVersionState(t, malformedClient, id, "", "", "duplicate")
	if statuses := malformedController.Status(); len(statuses) != 1 || statuses[0].Pending != 0 {
		t.Fatal("malformed legacy baseline replayed configuration")
	}
	malformedRaw := network.Config{Version: "duplicate", Management: duplicateBody}
	if _, err := malformedClient.ApplyConfig(t.Context(), id, malformedRaw); err != nil {
		t.Fatal(err)
	}
	malformedPersisted, err := os.ReadFile(malformedState)
	if err != nil {
		t.Fatal(err)
	}
	var malformedDevices []controller.Device
	if err := json.Unmarshal(malformedPersisted, &malformedDevices); err != nil {
		t.Fatal(err)
	}
	if len(malformedDevices) != 1 || malformedDevices[0].Baseline == nil || malformedDevices[0].Baseline.TypedReady || malformedDevices[0].Baseline.Config != malformedRaw {
		t.Fatal("raw duplicate-key baseline was changed or marked typed ready")
	}
	if reply := typedExchange(t, malformedController, id, key, report, false); reply.ManagementConfig != duplicateBody {
		t.Fatal("raw duplicate-key baseline changed before delivery")
	}

	failureDirectory := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(failureDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	failureState := filepath.Join(failureDirectory, "devices.json")
	writeTypedJSON(t, failureState, legacy)
	failureController := openTypedController(t, failureState)
	failureSocket := startTypedSocket(t, failureController)
	if err := os.Remove(failureState); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(failureDirectory); err != nil {
		t.Fatal(err)
	}
	writeTypedFixture(t, failureDirectory, []byte("blocks state directory"))
	failureClient := network.Dial(failureSocket)
	_, err = failureClient.ApplyConfig(t.Context(), id, network.Config{Version: "must-not-queue", Management: "cfgversion=must-not-queue\n"})
	assertControlFailure(t, err, network.PersistenceFailed, "")
	statuses := failureController.Status()
	if len(statuses) != 1 || statuses[0].Pending != 0 {
		t.Fatal("failed persistence queued raw configuration")
	}
	assertVersionState(t, failureClient, id, "", "", "legacy-v0")
}

func assertVersionState(t *testing.T, client *network.Client, id network.DeviceID, reported, desired, lastSetParam network.ConfigVersion) {
	t.Helper()
	snapshot, err := client.Device(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ReportedConfigVersion != reported || snapshot.DesiredConfigVersion != desired || snapshot.LastSetParamVersion != lastSetParam {
		t.Fatalf("versions = %q/%q/%q, want %q/%q/%q", snapshot.ReportedConfigVersion, snapshot.DesiredConfigVersion, snapshot.LastSetParamVersion, reported, desired, lastSetParam)
	}
}

func assertTypedMetadata(t *testing.T, reply controller.Reply, key string) configmap.Values {
	t.Helper()
	system, err := configmap.Parse(reply.SystemConfig)
	if err != nil {
		t.Fatal("invalid outgoing system configuration")
	}
	management, err := configmap.Parse(reply.ManagementConfig)
	if err != nil || management["authkey"] != key || management["inform_url"] != "http://192.0.2.1:8080/inform" || management["cfgversion"] != reply.ConfigVersion {
		t.Fatal("required connection metadata changed")
	}
	return system
}

func assertSameTypedIdentity(t *testing.T, first, current configmap.Values) {
	t.Helper()
	for _, name := range []string{"unifi.anonymous_controller_id", "unifi.anonymous_site_id", "unifi.reporterid", "unifi.siteid"} {
		if first[name] != current[name] {
			t.Fatalf("controller identity changed: %s", name)
		}
	}
}

func TestGenericConfigControlIntegration(t *testing.T) {
	t.Run("command and baseline ownership", testCommandAndBaselineOwnership)
	t.Run("explicit adoption SSH", testExplicitAdoptionSSH)
	t.Run("import AP identities", testImportAPIdentities)
	t.Run("transport persistence rollback", testTransportPersistenceRollback)
	directory := t.TempDir()
	state := filepath.Join(directory, "state.json")
	const key = "0123456789abcdef0123456789abcdef"
	const id network.DeviceID = "02:00:00:00:00:31"
	writeTypedJSON(t, state, []struct {
		MAC network.DeviceID `json:"mac"`
		Key string           `json:"key"`
	}{{MAC: id, Key: key}})
	controllerInstance := openTypedController(t, state)
	socket := startTypedSocket(t, controllerInstance)
	client := network.Dial(socket)
	initialState, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	invalidText := string([]byte{0xff})
	for _, invalid := range []network.Config{
		{Version: network.ConfigVersion(invalidText), Management: "unknown.key=value\n"},
		{Version: "generic-config-v1", Management: "unknown.key=" + invalidText + "\n"},
		{Version: "generic-config-v1", System: "unknown.key=" + invalidText + "\n"},
	} {
		_, err := client.ApplyConfig(t.Context(), id, invalid)
		assertControlFailure(t, err, network.InvalidEncoding, "")
		assertGenericConfigUnchanged(t, controllerInstance, state, initialState)
	}
	invalidFile := filepath.Join(directory, "invalid.cfg")
	writeTypedFixture(t, invalidFile, append([]byte("unknown.cli.key="), append([]byte{0xff}, '\n')...))
	if err := run(t.Context(), []string{"apply", "config", "--device", string(id), "--version", "generic-cli-v1", "--management-file", invalidFile, "--socket", socket}, io.Discard); err == nil {
		t.Fatal("config apply accepted invalid UTF-8")
	} else {
		assertControlFailure(t, err, network.InvalidEncoding, "")
	}
	assertGenericConfigUnchanged(t, controllerInstance, state, initialState)
	for _, invalid := range []network.Config{{Management: "unknown.key=value\n"}, {Version: "generic-config-v1"}} {
		_, err := client.ApplyConfig(t.Context(), id, invalid)
		assertControlFailure(t, err, network.InvalidConfig, "")
	}
	config := network.Config{
		Version:    "generic-config-v1",
		Management: "z=last\n\na=first\nunknown.management.key=value=with=equals\nunknown.management.trailing=preserve-space \n",
		System:     "unknown.security=operator\nrepeat=one\nrepeat=two\n\nunknown.system.key=quoted\\value\nunknown.system.empty=\nlabel=雪😀\n",
	}
	version, err := client.ApplyConfig(t.Context(), id, config)
	if err != nil {
		t.Fatal(err)
	}
	if version != config.Version {
		t.Fatalf("version = %q, want %q", version, config.Version)
	}

	persisted, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	var devices []struct {
		LastSetParam *controller.Reply `json:"last_setparam"`
	}
	if err := json.Unmarshal(persisted, &devices); err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].LastSetParam == nil || devices[0].LastSetParam.ConfigVersion != string(config.Version) || devices[0].LastSetParam.ManagementConfig != config.Management || devices[0].LastSetParam.SystemConfig != config.System {
		t.Fatal("controller did not persist the supplied configuration")
	}

	reply := typedExchange(t, controllerInstance, id, key, informmodel.Report{Model: "GenericDevice", Version: "1"}, false)
	if reply.Type != controller.ReplySetparam || reply.ConfigVersion != string(config.Version) || reply.ManagementConfig != config.Management || reply.SystemConfig != config.System {
		t.Fatal("inform response changed the supplied configuration")
	}

	managementFile := filepath.Join(directory, "management.cfg")
	management := "unknown.cli.key=exact value \n"
	writeTypedFixture(t, managementFile, []byte(management))
	var output bytes.Buffer
	if err := run(t.Context(), []string{"apply", "config", "--device", string(id), "--version", "generic-cli-v1", "--management-file", managementFile, "--socket", socket}, &output); err != nil {
		t.Fatal(err)
	}
	var queued queuedVersion
	if err := json.Unmarshal(output.Bytes(), &queued); err != nil {
		t.Fatal(err)
	}
	if queued.Version != "generic-cli-v1" {
		t.Fatalf("CLI version = %q", queued.Version)
	}
	reply = typedExchange(t, controllerInstance, id, key, informmodel.Report{Model: "GenericDevice", Version: "1"}, false)
	if reply.ConfigVersion != "generic-cli-v1" || reply.ManagementConfig != management || reply.SystemConfig != "" {
		t.Fatal("CLI changed configuration file content")
	}
	if err := run(t.Context(), []string{"apply", "config", "--device", string(id), "--version", "generic-cli-v2", "--file", managementFile}, io.Discard); err == nil {
		t.Fatal("config apply accepted a command JSON file")
	}
	if err := run(t.Context(), []string{"apply", "config", "--device", string(id), "--version", "generic-cli-v2"}, io.Discard); err == nil {
		t.Fatal("config apply accepted no configuration files")
	}
}

func TestRawConfigSocketEncoding(t *testing.T) {
	directory := t.TempDir()
	state := filepath.Join(directory, "state.json")
	const id network.DeviceID = "02:00:00:00:00:32"
	const key = "0123456789abcdef0123456789abcdef"
	controllerInstance := openTypedController(t, state)
	if err := controllerInstance.Register(string(id), key); err != nil {
		t.Fatal(err)
	}
	socket := startTypedSocket(t, controllerInstance)
	before, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	for _, body := range [][]byte{
		[]byte(`{"operation":"baseline-import","device":"02:00:00:00:00:32","baseline":{"config":{"version":"version","management":"key=value","system":"key=\ud800"}}}`),
		append([]byte(`{"operation":"baseline-import","device":"02:00:00:00:00:32","baseline":{"config":{"version":"version","management":"key=value","system":"key=`), append([]byte{0xff}, []byte(`"}}}`)...)...),
		append([]byte(`{"operation":"apply-config","device":"02:00:00:00:00:32","config":{"version":"`), append([]byte{0xff}, []byte(`","management":"key=value","system":""}}`)...)...),
		[]byte(`{"operation":"apply-config","device":"02:00:00:00:00:32","config":{"version":"version","management":"\ud800","system":""}}`),
		[]byte(`{"operation":"apply-config","device":"02:00:00:00:00:32","config":{"version":"version","management":"key=value","system":"\udc00"}}`),
		[]byte(`{"operation":"apply-config","device":"02:00:00:00:00:32","config":{"VERSION":"\ud800","MANAGEMENT":"key=value"}}`),
		[]byte(`{"operation":"apply-config","device":"02:00:00:00:00:32","config":{"version":"version","management":"\ud800"},"config":{"version":"version"}}`),
	} {
		if status := rawConfigStatus(t, client, body); status != http.StatusBadRequest {
			t.Fatalf("status = %d, want %d", status, http.StatusBadRequest)
		}
		assertGenericConfigUnchanged(t, controllerInstance, state, before)
	}

	valid := []byte(`{"operation":"apply-config","device":"02:00:00:00:00:32","config":{"version":"version-\ud83d\ude00","management":"literal-�","system":"unicode-雪"}}`)
	if status := rawConfigStatus(t, client, valid); status != http.StatusOK {
		t.Fatalf("status = %d, want %d", status, http.StatusOK)
	}
	persisted, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	var devices []controller.Device
	if err := json.Unmarshal(persisted, &devices); err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].LastSetParam == nil || devices[0].LastSetParam.ConfigVersion != "version-😀" || devices[0].LastSetParam.ManagementConfig != "literal-�" || devices[0].LastSetParam.SystemConfig != "unicode-雪" {
		t.Fatal("valid Unicode configuration changed")
	}
	reply := typedExchange(t, controllerInstance, id, key, informmodel.Report{Model: "RawSocketDevice", Version: "1"}, false)
	if reply.ConfigVersion != "version-😀" || reply.ManagementConfig != "literal-�" || reply.SystemConfig != "unicode-雪" {
		t.Fatal("valid Unicode configuration changed before delivery")
	}
}

func rawConfigStatus(t *testing.T, client *http.Client, body []byte) int {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://local/control", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	return response.StatusCode
}

func assertGenericConfigUnchanged(t *testing.T, controllerInstance *controller.Controller, state string, expectedState []byte) {
	t.Helper()
	actualState, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actualState, expectedState) {
		t.Fatal("invalid configuration changed persisted state")
	}
	status := controllerInstance.Status()
	if len(status) != 1 || status[0].Pending != 0 {
		t.Fatal("invalid configuration changed the command queue")
	}
}

func assertControlFailure(t *testing.T, err error, code network.ErrorCode, field string) {
	t.Helper()
	failure, ok := errors.AsType[*network.ControlError](err)
	if !ok || failure.Code != code || failure.Field != field {
		t.Fatalf("expected safe error %s at %s", code, field)
	}
	expected := string(code)
	if field != "" {
		expected += ": " + field
	}
	if failure.Error() != expected {
		t.Fatal("error contains unexpected content")
	}
}

func writeTypedFixture(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeTypedJSON[T any](t *testing.T, path string, value T) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	writeTypedFixture(t, path, data)
}

func openTypedController(t *testing.T, state string) *controller.Controller {
	t.Helper()
	c, err := controller.Open(state, "http://192.0.2.1:8080/inform", profile.NewRegistry(ap.New(), switches.New()))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func startTypedSocket(t *testing.T, c *controller.Controller) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "unifi-socket-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(directory); err != nil {
			t.Error(err)
		}
	})
	socket := filepath.Join(directory, "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(c.Control), ReadHeaderTimeout: time.Second}
	go func() {
		if err := server.Serve(listener); err != http.ErrServerClosed {
			t.Error(err)
		}
	}()
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
	})
	return socket
}

func typedExchange(t *testing.T, c *controller.Controller, id network.DeviceID, key string, report informmodel.Report, gcm bool) controller.Reply {
	t.Helper()
	if report.EthernetTable.Entries == nil {
		report.EthernetTable.Entries = []informmodel.Ethernet{}
	}
	payload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := net.ParseMAC(string(id))
	if err != nil {
		t.Fatal(err)
	}
	packet := inform.Packet{MAC: [6]byte(mac), Payload: payload}
	var encoded []byte
	if gcm {
		encoded, err = packet.EncodeGCM(key)
	} else {
		encoded, err = packet.Encode(key)
	}
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	c.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/inform", bytes.NewReader(encoded)))
	if response.Code != http.StatusOK {
		t.Fatalf("inform HTTP status %d", response.Code)
	}
	body, err := io.ReadAll(response.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	if binary.BigEndian.Uint32(body[4:8]) != 0 || binary.BigEndian.Uint32(body[32:36]) != 1 || (binary.BigEndian.Uint16(body[14:16])&8 != 0) != gcm {
		t.Fatal("controller framing changed")
	}
	decoded, err := inform.Decode(body, key)
	if err != nil {
		t.Fatal("reply could not decrypt")
	}
	var reply controller.Reply
	if err := json.Unmarshal(decoded.Payload, &reply); err != nil {
		t.Fatal(err)
	}
	return reply
}

func typedSeedBaseline(t *testing.T, family network.DeviceFamily, version network.ConfigVersion) *controller.ConfigurationBaseline {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "profiles", string(family), "baseline-setparam.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Management configmap.Values
		System     configmap.Values
	}
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	fixture.Management["cfgversion"] = string(version)
	if family == network.FamilyAP {
		fixture.System["radio.2.phyname"] = "wifi0"
	}
	// Credential policy is supplied separately by the tests that exercise it.
	for key := range fixture.System {
		if strings.HasPrefix(key, "sshd.") || strings.HasPrefix(key, "users.") {
			delete(fixture.System, key)
		}
	}
	management, err := fixture.Management.Encode()
	if err != nil {
		t.Fatal(err)
	}
	system, err := fixture.System.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return &controller.ConfigurationBaseline{SchemaVersion: 1, TypedReady: true, Config: network.Config{Version: version, Management: management, System: system}}
}

func testTypedBSSPersistence(t *testing.T, ctx context.Context, directory, key, secretPath string) {
	t.Helper()
	const id network.DeviceID = "02:00:00:00:00:15"
	const baselineVersion network.ConfigVersion = "bss-baseline"
	state := filepath.Join(directory, "bss-persistence.json")
	config, baseline := typedBSSFixture(t, secretPath, baselineVersion)
	writeTypedJSON(t, state, []controller.Device{{
		MAC:            string(id),
		Key:            key,
		Family:         network.FamilyAP,
		DesiredAP:      &config,
		DesiredVersion: baselineVersion,
		LastSetParam: &controller.Reply{
			Type:             controller.ReplySetparam,
			ConfigVersion:    string(baselineVersion),
			ManagementConfig: baseline.Config.Management,
			SystemConfig:     baseline.Config.System,
		},
		Baseline: baseline,
	}})
	controllerInstance := openTypedController(t, state)
	client := network.Dial(startTypedSocket(t, controllerInstance))
	report := informmodel.Report{
		Type:    "uap",
		Model:   "BSSFixtureAP",
		Version: "1",
		RadioTable: []informmodel.Radio{
			{Name: "wifi0", Radio: "ng", Widths: []informmodel.Uint16Scalar{20}},
			{Name: "wifi1", Radio: "na", Widths: []informmodel.Uint16Scalar{40}},
		},
		PortTable: []informmodel.Port{{Index: 1, Interface: "eth0"}},
	}
	if reply := typedExchange(t, controllerInstance, id, key, report, false); reply.Type != controller.ReplyNoop {
		t.Fatal("loaded BSS fixture replayed configuration")
	}

	unchanged, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	invalid := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{
		{Name: "fixture-legacy", BSSTransition: network.Supplied(network.BSSTransitionMode("automatic"))},
		{Name: "fixture-enabled"},
		{Name: "fixture-disabled"},
		{Name: "fixture-absent"},
	})}
	_, err = client.ApplyAP(ctx, id, invalid)
	assertControlFailure(t, err, network.InvalidConfig, "networks[0].bss_transition")
	afterInvalid, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterInvalid, unchanged) || controllerInstance.Status()[0].Pending != 0 {
		t.Fatal("invalid BSS Transition changed baseline, projection, or queue")
	}

	disableLegacy := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{
		{Name: "fixture-enabled"},
		{Name: "fixture-legacy", BSSTransition: network.Supplied(network.BSSTransitionDisabled)},
		{Name: "fixture-absent"},
		{Name: "fixture-disabled"},
	})}
	disabledVersion, err := client.ApplyAP(ctx, id, disableLegacy)
	if err != nil {
		t.Fatal(err)
	}
	disabledReply := typedExchange(t, controllerInstance, id, key, report, false)
	if disabledReply.Type != controller.ReplySetparam || disabledReply.ConfigVersion != string(disabledVersion) {
		t.Fatal("typed legacy-network disable was not delivered")
	}
	assertBSSFixtureValues(t, disabledReply.SystemConfig)
	report.ConfigVersion = string(disabledVersion)
	if reply := typedExchange(t, controllerInstance, id, key, report, false); reply.Type != controller.ReplyNoop {
		t.Fatal("matching BSS fixture inform received a command")
	}

	reloaded := openTypedController(t, state)
	restarted := network.Dial(startTypedSocket(t, reloaded))
	if reply := typedExchange(t, reloaded, id, key, report, true); reply.Type != controller.ReplyNoop {
		t.Fatal("BSS fixture command survived restart")
	}
	unrelated := network.APConfig{CountryCode: network.Supplied(uint16(124))}
	unrelatedVersion, err := restarted.ApplyAP(ctx, id, unrelated)
	if err != nil {
		t.Fatal(err)
	}
	unrelatedReply := typedExchange(t, reloaded, id, key, report, true)
	if unrelatedReply.Type != controller.ReplySetparam || unrelatedReply.ConfigVersion != string(unrelatedVersion) {
		t.Fatal("unrelated typed request was not delivered")
	}
	assertBSSFixtureValues(t, unrelatedReply.SystemConfig)

	persisted, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	var devices []controller.Device
	if err := json.Unmarshal(persisted, &devices); err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].LastSetParam == nil || devices[0].Baseline == nil || !devices[0].Baseline.TypedReady {
		t.Fatal("BSS fixture persisted state is incomplete")
	}
	if devices[0].LastSetParam.SystemConfig != unrelatedReply.SystemConfig || devices[0].Baseline.Config.System != unrelatedReply.SystemConfig {
		t.Fatal("last complete persisted body differs from the delivered reply")
	}
	assertBSSFixtureValues(t, devices[0].Baseline.Config.System)
}

func typedBSSFixture(t *testing.T, secretPath string, version network.ConfigVersion) (network.APConfig, *controller.ConfigurationBaseline) {
	t.Helper()
	baseline := typedSeedBaseline(t, network.FamilyAP, version)
	system, err := configmap.Parse(baseline.Config.System)
	if err != nil {
		t.Fatal(err)
	}
	system["radio.1.phyname"], system["radio.1.devname"] = "wifi1", "ath1"
	system["radio.2.phyname"], system["radio.2.devname"] = "wifi0", "ath0"
	type fixtureWLAN struct {
		index      string
		name       string
		parent     string
		deviceName string
		bss        string
		bssPresent bool
		bands      []network.RadioBand
	}
	wlans := []fixtureWLAN{
		{index: "1", name: "fixture-legacy", parent: "wifi0", deviceName: "ath0", bss: "enabled", bssPresent: true, bands: []network.RadioBand{network.Band2GHz, network.Band5GHz}},
		{index: "2", name: "fixture-legacy", parent: "wifi1", deviceName: "ath1", bss: "enabled", bssPresent: true},
		{index: "3", name: "fixture-enabled", parent: "wifi0", deviceName: "ath2", bss: "enabled", bssPresent: true, bands: []network.RadioBand{network.Band2GHz}},
		{index: "4", name: "fixture-disabled", parent: "wifi0", deviceName: "ath3", bss: "disabled", bssPresent: true, bands: []network.RadioBand{network.Band2GHz}},
		{index: "5", name: "fixture-absent", parent: "wifi0", deviceName: "ath4", bands: []network.RadioBand{network.Band2GHz}},
	}
	var networks []network.WiFiNetwork
	var bindings []profile.ResourceBinding
	for _, wlan := range wlans {
		wireless := "wireless." + wlan.index + "."
		aaa := "aaa." + wlan.index + "."
		netconf := "netconf." + wlan.index + "0."
		member := "bridge.1.port." + wlan.index + "0."
		system[wireless+"ssid"], system[wireless+"parent"], system[wireless+"devname"], system[wireless+"status"] = wlan.name, wlan.parent, wlan.deviceName, "enabled"
		system[aaa+"ssid"], system[aaa+"devname"], system[aaa+"status"], system[aaa+"br.devname"] = wlan.name, wlan.deviceName, "enabled", "br0"
		system[aaa+"wpa"], system[aaa+"wpa.1.pairwise"], system[aaa+"wpa.key.1.mgmt"], system[aaa+"wpa.psk"] = "2", "CCMP", "WPA-PSK", "fixture-passphrase"
		system[netconf+"devname"], system[netconf+"status"], system[netconf+"up"] = wlan.deviceName, "enabled", "disabled"
		system[member+"devname"] = wlan.deviceName
		if wlan.bssPresent {
			system[aaa+"bss_transition"] = wlan.bss
		}
		radioID := "ng"
		if wlan.parent == "wifi1" {
			radioID = "na"
		}
		bindings = append(bindings, profile.ResourceBinding{Kind: "wifi", Identity: wlan.name, RadioID: radioID, Prefixes: []string{wireless, aaa, netconf, member}})
		if len(wlan.bands) == 0 {
			continue
		}
		bss := network.Optional[network.BSSTransitionMode]{}
		if wlan.bssPresent {
			bss = network.Supplied(network.BSSTransitionMode(wlan.bss))
		}
		networks = append(networks, network.WiFiNetwork{
			Name: wlan.name, Enabled: network.Supplied(true), VLAN: network.Cleared[network.VLANID](),
			Bands: network.Supplied(wlan.bands), BSSTransition: bss,
			Security: network.Supplied(network.WiFiSecurity{
				Mode: network.Supplied(network.WPA2Personal), PSK: network.Supplied(network.SecretFile(secretPath)),
			}),
		})
	}
	systemBody, err := system.Encode()
	if err != nil {
		t.Fatal(err)
	}
	baseline.Config.System = systemBody
	baseline.Bindings = bindings
	config := network.APConfig{
		CountryCode: network.Supplied(uint16(840)),
		Radios: network.Supplied([]network.RadioConfig{
			{Band: network.Band2GHz, Enabled: network.Supplied(true), Channel: network.Cleared[uint16](), WidthMHz: network.Supplied(network.Width20), Power: network.Supplied(network.PowerConfig{Mode: network.Supplied(network.PowerAuto)})},
			{Band: network.Band5GHz, Enabled: network.Supplied(true), Channel: network.Cleared[uint16](), WidthMHz: network.Supplied(network.Width40), Power: network.Supplied(network.PowerConfig{Mode: network.Supplied(network.PowerAuto)})},
		}),
		Networks: network.Supplied(networks),
	}
	return config, baseline
}

func assertBSSFixtureValues(t *testing.T, body string) {
	t.Helper()
	values, err := configmap.Parse(body)
	if err != nil {
		t.Fatal("BSS fixture body is invalid")
	}
	for _, prefix := range []string{"aaa.1.", "aaa.2."} {
		if values[prefix+"bss_transition"] != "disabled" {
			t.Fatal("fixture-legacy BSS Transition is not disabled")
		}
	}
	if values["aaa.3.bss_transition"] != "enabled" || values["aaa.4.bss_transition"] != "disabled" {
		t.Fatal("peer BSS Transition changed")
	}
	if _, exists := values["aaa.5.bss_transition"]; exists {
		t.Fatal("absent peer BSS Transition acquired a default")
	}
}

func TestTypedApplyRequiresUsableBaseline(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef" // gitleaks:allow
	const id network.DeviceID = "02:00:00:00:00:51"
	tests := []struct {
		name     string
		baseline *controller.ConfigurationBaseline
		code     network.ErrorCode
	}{
		{name: "missing", code: network.BaselineRequired},
		{name: "raw ownership", baseline: &controller.ConfigurationBaseline{SchemaVersion: 1, TypedReady: false, Config: network.Config{Management: "ready=yes\n", System: "ready=yes\n"}}, code: network.BaselineUnusable},
		{name: "duplicate records", baseline: &controller.ConfigurationBaseline{SchemaVersion: 1, TypedReady: true, Config: network.Config{Management: "ready=yes\n", System: "same=1\nsame=2\n"}}, code: network.BaselineUnusable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := filepath.Join(t.TempDir(), "state.json")
			writeTypedJSON(t, state, []controller.Device{{MAC: string(id), Key: key, Baseline: test.baseline}})
			c := openTypedController(t, state)
			client := network.Dial(startTypedSocket(t, c))
			report := informmodel.Report{Type: "uap", RadioTable: []informmodel.Radio{{Name: "wifi0", Radio: "ng"}}}
			typedExchange(t, c, id, key, report, false)
			before, err := os.ReadFile(state)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.ApplyAP(t.Context(), id, network.APConfig{})
			assertControlFailure(t, err, test.code, "")
			after, err := os.ReadFile(state)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("failed typed apply changed persisted state")
			}
			if reply := typedExchange(t, c, id, key, report, false); reply.Type != controller.ReplyNoop {
				t.Fatal("failed typed apply queued configuration")
			}
		})
	}
}

func TestTypedApplyPersistenceFailurePreservesBaseline(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef" // gitleaks:allow
	const id network.DeviceID = "02:00:00:00:00:52"
	directory := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(directory, "devices.json")
	baseline := typedSeedBaseline(t, network.FamilyAP, "before")
	writeTypedJSON(t, state, []controller.Device{{MAC: string(id), Key: key, Baseline: baseline}})
	c := openTypedController(t, state)
	client := network.Dial(startTypedSocket(t, c))
	report := informmodel.Report{Type: "uap", RadioTable: []informmodel.Radio{{Name: "wifi0", Radio: "ng"}}}
	typedExchange(t, c, id, key, report, false)
	if err := os.Remove(state); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(directory); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(directory, []byte("blocked state directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := client.ApplyAP(t.Context(), id, network.APConfig{CountryCode: network.Supplied(uint16(840))})
	assertControlFailure(t, err, network.PersistenceFailed, "")
	snapshot, err := client.Device(t.Context(), id)
	if err != nil || snapshot.DesiredConfigVersion != "" || snapshot.LastSetParamVersion != "" {
		t.Fatal("failed persistence changed desired state")
	}
	if statuses := c.Status(); len(statuses) != 1 || statuses[0].Pending != 0 {
		t.Fatal("failed persistence changed queue")
	}
	if err := os.Remove(directory); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := c.Register(string(id), key); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	var devices []controller.Device
	if err := json.Unmarshal(body, &devices); err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].Baseline == nil || devices[0].Baseline.Config != baseline.Config {
		t.Fatal("failed persistence changed in-memory baseline")
	}
}
