package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"goodkind.io/unifi-go/internal/configmap"
	"goodkind.io/unifi-go/internal/controller"
	"goodkind.io/unifi-go/internal/informmodel"
	"goodkind.io/unifi-go/internal/profile"
	"goodkind.io/unifi-go/network"
)

type resourceControlResponse struct {
	Error        *network.ControlError     `json:"error,omitempty"`
	Version      network.ConfigVersion     `json:"version,omitempty"`
	WiFiNetworks []network.WiFiNetworkView `json:"wifi_networks,omitempty"`
}

func testResourceMutations(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	directory := t.TempDir()
	state := filepath.Join(directory, "state.json")
	const key = "0123456789abcdef0123456789abcdef" // gitleaks:allow
	const apID network.DeviceID = "02:00:00:00:01:11"
	const switchID network.DeviceID = "02:00:00:00:01:12"
	sourceSecret := filepath.Join(directory, "source-secret")
	destinationSecret := filepath.Join(directory, "destination-secret")
	equivalentSecret := filepath.Join(directory, "equivalent-secret")
	apSSHSecret := filepath.Join(directory, "ap-ssh-secret")
	switchSSHSecret := filepath.Join(directory, "switch-ssh-secret")
	sourceMaterial := bytes.Repeat([]byte{'s'}, 24)
	destinationMaterial := bytes.Repeat([]byte{'d'}, 24)
	apSSHMaterial := bytes.Repeat([]byte{'a'}, 24)
	switchSSHMaterial := bytes.Repeat([]byte{'w'}, 24)
	writeTypedFixture(t, sourceSecret, sourceMaterial)
	writeTypedFixture(t, destinationSecret, destinationMaterial)
	writeTypedFixture(t, equivalentSecret, destinationMaterial)
	writeTypedFixture(t, apSSHSecret, apSSHMaterial)
	writeTypedFixture(t, switchSSHSecret, switchSSHMaterial)
	writeTypedJSON(t, state, []controller.Device{
		{MAC: string(apID), Key: key, Baseline: typedSeedBaseline(t, network.FamilyAP, "seed")},
		{MAC: string(switchID), Key: key, Baseline: typedSeedBaseline(t, network.FamilySwitch, "seed")},
	})
	managed := openTypedController(t, state)
	socket := startTypedSocket(t, managed)
	apReport := resourceAPReport()
	switchReport := resourceSwitchReport()
	typedExchange(t, managed, apID, key, apReport, false)
	typedExchange(t, managed, switchID, key, switchReport, true)
	assertResourceFailure(t, callResourceControl(t, socket, controller.ControlRequest{
		Operation: "wifi-list", Device: apID,
	}), network.DesiredStateMissing)
	apConfig := typedAPFixture(sourceSecret)
	apConfig.Radios.Value[0].ID = "wifi0"
	apConfig.SSH = resourceSSH("ap-operator", apSSHSecret)
	apVersion, err := network.Dial(socket).ApplyAP(ctx, apID, apConfig)
	if err != nil {
		t.Fatal(err)
	}
	switchConfig := typedSwitchFixture()
	switchConfig.SSH = resourceSSH("switch-operator", switchSSHSecret)
	switchVersion, err := network.Dial(socket).ApplySwitch(ctx, switchID, switchConfig)
	if err != nil {
		t.Fatal(err)
	}
	apReport.ConfigVersion = string(apVersion)
	switchReport.ConfigVersion = string(switchVersion)
	typedExchange(t, managed, apID, key, apReport, false)
	typedExchange(t, managed, switchID, key, switchReport, true)
	apVersion = importSourceExtension(t, ctx, socket, state, apID)
	apReport.ConfigVersion = string(apVersion)
	typedExchange(t, managed, apID, key, apReport, false)
	beforeInvalidPower := readResourceState(t, state)
	invalidPower := network.RadioConfig{
		ID:    "wifi0",
		Power: network.Supplied(network.PowerConfig{DBm: network.Supplied(10)}),
	}
	invalidPowerResponse := callResourceControl(t, socket, controller.ControlRequest{
		Operation: "radio-set", Device: apID, Radio: &invalidPower,
	})
	if invalidPowerResponse.Error == nil || invalidPowerResponse.Error.Code != network.InvalidConfig || invalidPowerResponse.Error.Field != "radios[0].power.dbm" {
		t.Fatal("invalid merged radio power was accepted")
	}
	if !bytes.Equal(beforeInvalidPower, readResourceState(t, state)) || resourcePending(managed, apID) != 0 {
		t.Fatal("invalid merged radio power changed state or queue")
	}
	beforeInvalidPort := readResourceState(t, state)
	invalidPort := network.SwitchPortConfig{Index: 1, TaggedVLANs: network.Supplied([]network.VLANID{20})}
	invalidPortResponse := callResourceControl(t, socket, controller.ControlRequest{
		Operation: "port-set", Device: switchID, Port: &invalidPort,
	})
	if invalidPortResponse.Error == nil || invalidPortResponse.Error.Code != network.InvalidConfig || invalidPortResponse.Error.Field != "ports[0].tagged_vlans[0]" {
		t.Fatal("invalid merged switch port policy was accepted")
	}
	if !bytes.Equal(beforeInvalidPort, readResourceState(t, state)) || resourcePending(managed, switchID) != 0 {
		t.Fatal("invalid merged switch port policy changed state or queue")
	}
	apCredentials := readResourceCredentialPolicy(t, state, apID, "Documentation")
	if err := os.Remove(sourceSecret); err != nil {
		t.Fatal(err)
	}
	apVersion = setResourceRadio(t, socket, managed, apID, key, &apReport, false)
	assertResourceCredentialPolicy(t, state, apID, "Documentation", apCredentials)
	writeTypedFixture(t, sourceSecret, sourceMaterial)
	writeTypedFixture(t, apSSHSecret, bytes.Repeat([]byte{'z'}, 24))
	apVersion = setResourceRadio(t, socket, managed, apID, key, &apReport, true)
	assertResourceCredentialPolicy(t, state, apID, "Documentation", apCredentials)
	writeTypedFixture(t, apSSHSecret, apSSHMaterial)
	switchCredentials := readResourceCredentialPolicy(t, state, switchID, "")
	if err := os.Remove(switchSSHSecret); err != nil {
		t.Fatal(err)
	}
	switchVersion = setResourcePort(t, socket, managed, switchID, key, &switchReport, true)
	assertResourceCredentialPolicy(t, state, switchID, "", switchCredentials)
	writeTypedFixture(t, switchSSHSecret, switchSSHMaterial)

	beforeAdd := readResourceState(t, state)
	beforePending := resourcePending(managed, apID)
	assertResourceFailure(t, callResourceControl(t, socket, controller.ControlRequest{
		Operation: "wifi-add", Device: apID,
	}), network.InvalidConfig)
	conflictingRadio := apConfig.Radios.Value[0]
	assertResourceFailure(t, callResourceControl(t, socket, controller.ControlRequest{
		Operation: "wifi-add", Device: apID, Radio: &conflictingRadio,
		WiFiAdd: resourceAddWiFi("Destination", destinationSecret, "Documentation"),
	}), network.InvalidConfig)
	assertResourceFailure(t, callResourceControl(t, socket, controller.ControlRequest{
		Operation: "wifi-add", Device: apID,
		WiFiAdd: resourceAddWiFi("Destination", destinationSecret, "Missing"),
	}), network.ResourceNotFound)
	assertResourceFailure(t, callResourceControl(t, socket, controller.ControlRequest{
		Operation: "wifi-add", Device: switchID,
		WiFiAdd: resourceAddWiFi("Destination", destinationSecret, "Documentation"),
	}), network.FamilyMismatch)
	if !bytes.Equal(beforeAdd, readResourceState(t, state)) || resourcePending(managed, apID) != beforePending {
		t.Fatal("failed resource requests changed state or queue")
	}
	backup := state + ".saved"
	if err := os.Rename(state, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	assertResourceFailure(t, callResourceControl(t, socket, controller.ControlRequest{
		Operation: "wifi-add", Device: apID,
		WiFiAdd: resourceAddWiFi("Destination", destinationSecret, "Documentation"),
	}), network.PersistenceFailed)
	if resourcePending(managed, apID) != beforePending || len(callResourceControl(t, socket, controller.ControlRequest{Operation: "wifi-list", Device: apID}).WiFiNetworks) != 1 {
		t.Fatal("failed persistence changed in-memory desired state or queue")
	}
	if err := os.Remove(state); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backup, state); err != nil {
		t.Fatal(err)
	}
	added := callResourceControl(t, socket, controller.ControlRequest{
		Operation: "wifi-add", Device: apID,
		WiFiAdd: resourceAddWiFi("Destination", destinationSecret, "Documentation"),
	})
	if added.Error != nil || added.Version == "" || added.Version == apVersion {
		t.Fatal("WiFi add did not queue a new version")
	}
	queued := typedExchange(t, managed, apID, key, apReport, false)
	assertCopiedWiFi(t, queued, "Documentation", "Destination", sourceMaterial, destinationMaterial)
	assertResourceFailure(t, callResourceControl(t, socket, controller.ControlRequest{
		Operation: "wifi-remove", Device: apID, WiFiRemove: resourceString("Destination"),
	}), network.ConfigurationPending)
	_, err = network.Dial(socket).ApplyAP(ctx, apID, apConfig)
	assertControlFailure(t, err, network.ConfigurationPending, "")
	listed := callResourceControl(t, socket, controller.ControlRequest{Operation: "wifi-list", Device: apID})
	if listed.Error != nil || len(listed.WiFiNetworks) != 2 {
		t.Fatal("safe WiFi list unavailable while pending")
	}
	if listed.WiFiNetworks[0].Name != "Destination" || listed.WiFiNetworks[1].Name != "Documentation" {
		t.Fatal("safe WiFi list is not sorted")
	}
	assertNoWiFiSecrets(t, listed, sourceSecret, destinationSecret)
	apReport.ConfigVersion = string(added.Version)
	typedExchange(t, managed, apID, key, apReport, false)
	assertResourceFailure(t, callResourceControl(t, socket, controller.ControlRequest{
		Operation: "wifi-add", Device: apID,
		WiFiAdd: resourceAddWiFi("Destination", destinationSecret, "Documentation"),
	}), network.ResourceExists)
	apReport.ConfigVersion = "reported-drift"
	typedExchange(t, managed, apID, key, apReport, false)
	beforeFailure := readResourceState(t, state)
	assertResourceFailure(t, callResourceControl(t, socket, controller.ControlRequest{
		Operation: "wifi-remove", Device: apID, WiFiRemove: resourceString("Destination"),
	}), network.ConfigurationDrift)
	beforeFailurePending := resourcePending(managed, apID)
	if !bytes.Equal(beforeFailure, readResourceState(t, state)) || resourcePending(managed, apID) != beforeFailurePending {
		t.Fatal("failed mutation changed persisted state or queue")
	}
	listed = callResourceControl(t, socket, controller.ControlRequest{Operation: "wifi-list", Device: apID})
	if listed.Error != nil || len(listed.WiFiNetworks) != 2 {
		t.Fatal("safe WiFi list unavailable during drift")
	}

	restoredConfig := apConfig.Clone()
	restoredConfig.Networks.Value = append(restoredConfig.Networks.Value, network.WiFiNetwork{
		Name: "Destination", Enabled: network.Supplied(true), VLAN: network.Cleared[network.VLANID](),
		RadioIDs:      network.Supplied([]network.RadioID{"wifi0"}),
		BSSTransition: network.Supplied(network.BSSTransitionEnabled),
		Security: network.Supplied(network.WiFiSecurity{
			Mode: network.Supplied(network.WPA2Personal), PSK: network.Supplied(network.SecretFile(destinationSecret)),
		}),
	})
	restoredVersion, err := network.Dial(socket).ApplyAP(ctx, apID, restoredConfig)
	if err != nil {
		t.Fatal(err)
	}
	apReport.ConfigVersion = string(restoredVersion)
	typedExchange(t, managed, apID, key, apReport, false)

	replacement := network.WiFiNetwork{
		Name:          "Renamed",
		BSSTransition: network.Supplied(network.BSSTransitionDisabled),
	}
	set := callResourceControl(t, socket, controller.ControlRequest{
		Operation: "wifi-set", Device: apID,
		WiFiSet: &network.SetWiFiRequest{CurrentName: "Destination", Network: replacement},
	})
	if set.Error != nil || set.Version == "" {
		t.Fatal("WiFi set failed")
	}
	apReport.ConfigVersion = string(set.Version)
	renamedReply := typedExchange(t, managed, apID, key, apReport, false)
	assertCopiedWiFi(t, renamedReply, "Documentation", "Renamed", sourceMaterial, destinationMaterial)
	replacement = network.WiFiNetwork{
		Name: "Renamed",
		Security: network.Supplied(network.WiFiSecurity{
			PSK: network.Supplied(network.SecretFile(equivalentSecret)),
		}),
	}
	equivalent := callResourceControl(t, socket, controller.ControlRequest{
		Operation: "wifi-set", Device: apID,
		WiFiSet: &network.SetWiFiRequest{CurrentName: "Renamed", Network: replacement},
	})
	if equivalent.Error != nil || equivalent.Version != set.Version {
		t.Fatal("equivalent secret changed compiled version")
	}
	if reply := typedExchange(t, managed, apID, key, apReport, false); reply.Type != controller.ReplyNoop {
		t.Fatal("equivalent secret queued duplicate configuration")
	}
	assertPersistedWiFiPolicy(t, state, equivalentSecret)

	radio := network.RadioConfig{ID: "wifi0", Enabled: network.Supplied(false)}
	radioResult := callResourceControl(t, socket, controller.ControlRequest{Operation: "radio-set", Device: apID, Radio: &radio})
	if radioResult.Error != nil || radioResult.Version == equivalent.Version {
		t.Fatal("stable radio mutation failed")
	}
	if reply := typedExchange(t, managed, apID, key, apReport, false); reply.Type != controller.ReplySetparam || reply.ConfigVersion != string(radioResult.Version) {
		t.Fatal("stable radio mutation was not delivered")
	}
	apReport.ConfigVersion = string(radioResult.Version)
	typedExchange(t, managed, apID, key, apReport, false)
	port := switchConfig.Ports.Value[0]
	port.Enabled = network.Supplied(false)
	portResult := callResourceControl(t, socket, controller.ControlRequest{Operation: "port-set", Device: switchID, Port: &port})
	if portResult.Error != nil || portResult.Version == switchVersion {
		t.Fatal("physical port mutation failed")
	}
	if reply := typedExchange(t, managed, switchID, key, switchReport, true); reply.Type != controller.ReplySetparam || reply.ConfigVersion != string(portResult.Version) {
		t.Fatal("physical port mutation was not delivered")
	}
	removed := callResourceControl(t, socket, controller.ControlRequest{
		Operation: "wifi-remove", Device: apID, WiFiRemove: resourceString("Renamed"),
	})
	if removed.Error != nil || removed.Version == "" {
		t.Fatal("WiFi remove failed")
	}
	apReport.ConfigVersion = string(removed.Version)
	typedExchange(t, managed, apID, key, apReport, false)
	assertRemovedWiFi(t, state)

	restarted := openTypedController(t, state)
	restartedSocket := startTypedSocket(t, restarted)
	finalList := callResourceControl(t, restartedSocket, controller.ControlRequest{Operation: "wifi-list", Device: apID})
	if finalList.Error != nil || len(finalList.WiFiNetworks) != 1 {
		t.Fatal("final desired resources did not survive restart")
	}
	if reply := typedExchange(t, restarted, apID, key, apReport, false); reply.Type != controller.ReplyNoop {
		t.Fatal("AP resource queue survived restart")
	}
	if reply := typedExchange(t, restarted, switchID, key, switchReport, true); reply.Type != controller.ReplyNoop {
		t.Fatal("switch resource queue survived restart")
	}
	if len(beforeAdd) == 0 {
		t.Fatal("initial state was not persisted")
	}
}

func resourceAPReport() informmodel.Report {
	report := informmodel.Report{
		Type: "uap", Model: "DocumentationAP", Version: "1",
		RadioTable: []informmodel.Radio{{Name: "wifi0", Radio: "ng", Widths: []informmodel.Uint16Scalar{20}}},
		PortTable:  []informmodel.Port{{Index: 1, Interface: "eth0"}},
		VAPTable:   []informmodel.VAP{{Name: "ath0", Radio: "ng", ESSID: "Documentation"}},
	}
	return report
}

func resourceSwitchReport() informmodel.Report {
	up := true
	capability := uint64(1)
	return informmodel.Report{
		Type: "usw", Model: "DocumentationSwitch", Version: "1",
		PortTable:  []informmodel.Port{{Index: 1, Interface: "eth0", Up: &up, PoECaps: &capability}},
		SwitchCaps: &informmodel.SwitchCapabilities{VLANCaps: &capability},
	}
}

func callResourceControl(t *testing.T, socket string, request controller.ControlRequest) resourceControlResponse {
	t.Helper()
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport}).Post("http://local/control", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var envelope resourceControlResponse
	if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func assertResourceFailure(t *testing.T, response resourceControlResponse, code network.ErrorCode) {
	t.Helper()
	if response.Error == nil || response.Error.Code != code || response.Error.Field != "" {
		t.Fatalf("expected safe resource error %s", code)
	}
}

func assertNoWiFiSecrets(t *testing.T, response resourceControlResponse, secretPaths ...string) {
	t.Helper()
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, secretPath := range secretPaths {
		if bytes.Contains(encoded, []byte(secretPath)) {
			t.Fatal("safe WiFi view exposed a secret path")
		}
	}
}

func assertCopiedWiFi(t *testing.T, reply controller.Reply, sourceName, destinationName string, sourceSecret, destinationSecret []byte) {
	t.Helper()
	if !bytes.Contains([]byte(reply.SystemConfig), []byte(sourceName)) || !bytes.Contains([]byte(reply.SystemConfig), []byte(destinationName)) {
		t.Fatal("copied WiFi names missing")
	}
	if !bytes.Contains([]byte(reply.SystemConfig), sourceSecret) || !bytes.Contains([]byte(reply.SystemConfig), destinationSecret) {
		t.Fatal("copied WiFi credentials missing")
	}
	values, err := configmap.Parse(reply.SystemConfig)
	if err != nil {
		t.Fatal(err)
	}
	sourceParent, sourceBridge := wifiTargets(values, sourceName)
	destinationParent, destinationBridge := wifiTargets(values, destinationName)
	if sourceParent == "" || sourceParent != destinationParent || sourceBridge == "" || sourceBridge != destinationBridge {
		t.Fatal("copied WiFi changed VLAN or radio targets")
	}
	sourcePrefix, err := profile.MatchRecord(values, "wireless.", "ssid", sourceName)
	if err != nil {
		t.Fatal(err)
	}
	destinationPrefix, err := profile.MatchRecord(values, "wireless.", "ssid", destinationName)
	if err != nil {
		t.Fatal(err)
	}
	if values[sourcePrefix+"fixture_extension"] != "preserved-marker" || values[destinationPrefix+"fixture_extension"] != "preserved-marker" {
		t.Fatal("copied WiFi lost an untyped source record")
	}
}

func wifiTargets(values configmap.Values, name string) (string, string) {
	var parent, bridge string
	for _, prefix := range profile.RecordPrefixes(values, "wireless.") {
		if values[prefix+"ssid"] == name {
			parent = values[prefix+"parent"]
		}
	}
	for _, prefix := range profile.RecordPrefixes(values, "aaa.") {
		if values[prefix+"ssid"] == name {
			bridge = values[prefix+"br.devname"]
		}
	}
	return parent, bridge
}

func assertPersistedWiFiPolicy(t *testing.T, state, expected string) {
	t.Helper()
	data := readResourceState(t, state)
	var devices []controller.Device
	if err := json.Unmarshal(data, &devices); err != nil {
		t.Fatal(err)
	}
	if len(devices) == 0 || devices[0].DesiredAP == nil {
		t.Fatal("replacement WiFi policy was not persisted")
	}
	wifi := devices[0].DesiredAP.Networks.Value[1]
	source := devices[0].DesiredAP.Networks.Value[0]
	if wifi.Security.Value.PSK.Value != network.SecretFile(expected) || wifi.BSSTransition.Value != network.BSSTransitionDisabled || source.BSSTransition.Value != network.BSSTransitionEnabled {
		t.Fatal("omitted WiFi policy was not preserved")
	}
}

func assertRemovedWiFi(t *testing.T, state string) {
	t.Helper()
	data := readResourceState(t, state)
	var devices []controller.Device
	if err := json.Unmarshal(data, &devices); err != nil {
		t.Fatal(err)
	}
	if len(devices) == 0 || devices[0].Baseline == nil {
		t.Fatal("final WiFi baseline is unavailable")
	}
	system, err := configmap.Parse(devices[0].Baseline.Config.System)
	if err != nil {
		t.Fatal(err)
	}
	source, err := profile.MatchRecord(system, "wireless.", "ssid", "Documentation")
	if err != nil || source == "" || system[source+"fixture_extension"] != "preserved-marker" {
		t.Fatal("WiFi removal changed the source record")
	}
	destination, err := profile.MatchRecord(system, "wireless.", "ssid", "Destination")
	if err != nil || destination != "" {
		t.Fatal("WiFi removal retained the pre-rename record")
	}
	renamed, err := profile.MatchRecord(system, "wireless.", "ssid", "Renamed")
	if err != nil || renamed != "" {
		t.Fatal("WiFi removal retained an owned record")
	}
	if system["locale.timezone"] != "UTC0" {
		t.Fatal("WiFi removal changed unrelated baseline policy")
	}
}

func readResourceState(t *testing.T, state string) []byte {
	t.Helper()
	data, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func importSourceExtension(t *testing.T, ctx context.Context, socket, state string, id network.DeviceID) network.ConfigVersion {
	t.Helper()
	data := readResourceState(t, state)
	var devices []controller.Device
	if err := json.Unmarshal(data, &devices); err != nil {
		t.Fatal(err)
	}
	index := -1
	for candidateIndex := range devices {
		if devices[candidateIndex].MAC == string(id) {
			index = candidateIndex
		}
	}
	if index < 0 || devices[index].Baseline == nil || devices[index].DesiredAP == nil {
		t.Fatal("applied source baseline is unavailable")
	}
	management, err := configmap.Parse(devices[index].Baseline.Config.Management)
	if err != nil {
		t.Fatal(err)
	}
	system, err := configmap.Parse(devices[index].Baseline.Config.System)
	if err != nil {
		t.Fatal(err)
	}
	prefix, err := profile.MatchRecord(system, "wireless.", "ssid", "Documentation")
	if err != nil || prefix == "" {
		t.Fatal("source WiFi record is unavailable")
	}
	system[prefix+"fixture_extension"] = "preserved-marker"
	version, err := profile.CanonicalVersion(profile.SetParam{Version: "", Management: management, System: system})
	if err != nil {
		t.Fatal(err)
	}
	management["cfgversion"] = string(version)
	managementBody, err := management.Encode()
	if err != nil {
		t.Fatal(err)
	}
	systemBody, err := system.Encode()
	if err != nil {
		t.Fatal(err)
	}
	config := network.Config{Version: version, Management: managementBody, System: systemBody}
	if err := network.Dial(socket).ImportBaseline(ctx, id, network.BaselineImport{Config: config, AP: devices[index].DesiredAP, Switch: nil}); err != nil {
		t.Fatal(err)
	}
	return version
}

func resourcePending(managed *controller.Controller, id network.DeviceID) int {
	for _, status := range managed.Status() {
		if status.MAC == string(id) {
			return status.Pending
		}
	}
	return -1
}

func resourceString(value string) *string { return &value }

func resourceAddWiFi(name, passwordPath, copyFrom string) *network.AddWiFiRequest {
	return &network.AddWiFiRequest{Name: name, Password: network.SecretFile(passwordPath), CopyFrom: copyFrom} // gitleaks:allow
}

func resourceSSH(username, passwordPath string) network.Optional[network.SSHConfig] {
	return network.Supplied(network.SSHConfig{
		Username: network.Supplied(username),
		Password: network.Supplied(network.SecretFile(passwordPath)), // gitleaks:allow
	})
}

func setResourceRadio(t *testing.T, socket string, managed *controller.Controller, id network.DeviceID, key string, report *informmodel.Report, enabled bool) network.ConfigVersion {
	t.Helper()
	radio := network.RadioConfig{ID: "wifi0", Enabled: network.Supplied(enabled)}
	result := callResourceControl(t, socket, controller.ControlRequest{Operation: "radio-set", Device: id, Radio: &radio})
	if result.Error != nil || result.Version == "" {
		t.Fatal("stable radio mutation failed")
	}
	if reply := typedExchange(t, managed, id, key, *report, false); reply.Type != controller.ReplySetparam || reply.ConfigVersion != string(result.Version) {
		t.Fatal("stable radio mutation was not delivered")
	}
	report.ConfigVersion = string(result.Version)
	typedExchange(t, managed, id, key, *report, false)
	return result.Version
}

func setResourcePort(t *testing.T, socket string, managed *controller.Controller, id network.DeviceID, key string, report *informmodel.Report, enabled bool) network.ConfigVersion {
	t.Helper()
	port := network.SwitchPortConfig{Index: 1, Enabled: network.Supplied(enabled)}
	result := callResourceControl(t, socket, controller.ControlRequest{Operation: "port-set", Device: id, Port: &port})
	if result.Error != nil || result.Version == "" {
		t.Fatal("physical port mutation failed")
	}
	if reply := typedExchange(t, managed, id, key, *report, true); reply.Type != controller.ReplySetparam || reply.ConfigVersion != string(result.Version) {
		t.Fatal("physical port mutation was not delivered")
	}
	report.ConfigVersion = string(result.Version)
	typedExchange(t, managed, id, key, *report, true)
	return result.Version
}

type resourceCredentialPolicy struct {
	wifiPSK     string
	sshUsername string
	sshPassword string
}

func readResourceCredentialPolicy(t *testing.T, state string, id network.DeviceID, wifiName string) resourceCredentialPolicy {
	t.Helper()
	var devices []controller.Device
	if err := json.Unmarshal(readResourceState(t, state), &devices); err != nil {
		t.Fatal(err)
	}
	for _, device := range devices {
		if device.MAC != string(id) || device.Baseline == nil {
			continue
		}
		values, err := configmap.Parse(device.Baseline.Config.System)
		if err != nil {
			t.Fatal(err)
		}
		policy := resourceCredentialPolicy{sshUsername: values["users.1.name"], sshPassword: values["users.1.password"]}
		if wifiName == "" {
			return policy
		}
		prefix, err := profile.MatchRecord(values, "aaa.", "ssid", wifiName)
		if err != nil || prefix == "" {
			t.Fatal("WiFi credential policy is unavailable")
		}
		policy.wifiPSK = values[prefix+"wpa.psk"]
		return policy
	}
	t.Fatal("device credential policy is unavailable")
	return resourceCredentialPolicy{}
}

func assertResourceCredentialPolicy(t *testing.T, state string, id network.DeviceID, wifiName string, expected resourceCredentialPolicy) {
	t.Helper()
	if readResourceCredentialPolicy(t, state, id, wifiName) != expected {
		t.Fatal("resource mutation changed unrelated credential policy")
	}
}
