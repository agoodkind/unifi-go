package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"goodkind.io/unifi-go/internal/configmap"
	"goodkind.io/unifi-go/internal/controller"
	"goodkind.io/unifi-go/internal/informmodel"
	"goodkind.io/unifi-go/internal/profile"
	"goodkind.io/unifi-go/network"
)

func testPublicResourceAPIAndCLI(t *testing.T) {
	t.Helper()
	ctx := t.Context()
	directory := t.TempDir()
	state := filepath.Join(directory, "state.json")
	const key = "0123456789abcdef0123456789abcdef" // gitleaks:allow
	const apID network.DeviceID = "02:00:00:00:02:11"
	const switchID network.DeviceID = "02:00:00:00:02:12"
	const storedHash = "$6$synthetic$resource-cli" // gitleaks:allow
	sourceSecret := filepath.Join(directory, "source-secret")
	addedSecret := filepath.Join(directory, "added-secret")
	sourceMaterial := bytes.Repeat([]byte{'s'}, 24)
	destinationMaterial := bytes.Repeat([]byte{'a'}, 24)
	writeTypedFixture(t, sourceSecret, sourceMaterial)
	writeTypedFixture(t, addedSecret, destinationMaterial)
	apBaseline := typedSeedBaseline(t, network.FamilyAP, "seed")
	apBaseline.Config.System += "users.1.password=" + storedHash + "\n"
	writeTypedJSON(t, state, []controller.Device{
		{MAC: string(apID), Key: key, Baseline: apBaseline},
		{MAC: string(switchID), Key: key, Baseline: typedSeedBaseline(t, network.FamilySwitch, "seed")},
	})
	managed := openTypedController(t, state)
	socket := startTypedSocket(t, managed)
	client := network.Dial(socket)
	apReport := resourceAPReport()
	switchReport := resourceSwitchReport()
	typedExchange(t, managed, apID, key, apReport, false)
	typedExchange(t, managed, switchID, key, switchReport, true)
	apConfig := typedAPFixture(sourceSecret)
	apConfig.Radios.Value[0].ID = "wifi0"
	apVersion, err := client.ApplyAP(ctx, apID, apConfig)
	if err != nil {
		t.Fatal(err)
	}
	switchConfig := typedSwitchFixture()
	switchVersion, err := client.ApplySwitch(ctx, switchID, switchConfig)
	if err != nil {
		t.Fatal(err)
	}
	apReport.ConfigVersion = string(apVersion)
	switchReport.ConfigVersion = string(switchVersion)
	typedExchange(t, managed, apID, key, apReport, false)
	typedExchange(t, managed, switchID, key, switchReport, true)

	networks, err := client.WiFiNetworks(ctx, apID)
	if err != nil || len(networks) != 1 {
		t.Fatal("public WiFi list failed")
	}
	assertPublicResourceOutputSafe(t, networks, key, sourceSecret, addedSecret, storedHash, string(sourceMaterial), string(destinationMaterial))
	apVersion, err = client.AddWiFi(ctx, apID, network.AddWiFiRequest{Name: "Added", Password: network.SecretFile(addedSecret), CopyFrom: "Documentation"}) // gitleaks:allow
	if err != nil {
		t.Fatal(err)
	}
	apReport = acknowledgePublicResource(t, managed, apID, key, apReport, apVersion, false)
	apVersion, err = client.SetWiFi(ctx, apID, network.SetWiFiRequest{CurrentName: "Added", Network: network.WiFiNetwork{
		Name: "Renamed", BSSTransition: network.Supplied(network.BSSTransitionDisabled),
	}})
	if err != nil {
		t.Fatal(err)
	}
	reply := typedExchange(t, managed, apID, key, apReport, false)
	assertPublicBSSPolicy(t, reply.SystemConfig, "Documentation", "Renamed")
	apReport.ConfigVersion = string(apVersion)
	typedExchange(t, managed, apID, key, apReport, false)
	apVersion, err = client.SetRadio(ctx, apID, network.RadioConfig{ID: "wifi0", Enabled: network.Supplied(false)})
	if err != nil {
		t.Fatal(err)
	}
	apReport = acknowledgePublicResource(t, managed, apID, key, apReport, apVersion, false)
	switchVersion, err = client.SetSwitchPort(ctx, switchID, network.SwitchPortConfig{Index: 1, Enabled: network.Supplied(true)})
	if err != nil {
		t.Fatal(err)
	}
	switchReport = acknowledgePublicResource(t, managed, switchID, key, switchReport, switchVersion, true)
	apVersion, err = client.RemoveWiFi(ctx, apID, "Renamed")
	if err != nil {
		t.Fatal(err)
	}
	apReport = acknowledgePublicResource(t, managed, apID, key, apReport, apVersion, false)

	nameFile := filepath.Join(directory, "name")
	copyFile := filepath.Join(directory, "copy")
	currentFile := filepath.Join(directory, "current")
	writeTypedFixture(t, nameFile, []byte("CLI Added\r\n"))
	writeTypedFixture(t, copyFile, []byte("Documentation\n"))
	writeTypedFixture(t, currentFile, []byte("CLI Added\n"))
	var output bytes.Buffer
	if err := run(ctx, []string{"wifi", "list", "--socket", socket}, &output); err != nil {
		t.Fatal(err)
	}
	assertPublicResourceOutputSafe(t, output.String(), key, sourceSecret, addedSecret, storedHash, string(sourceMaterial), string(destinationMaterial))
	output.Reset()
	if err := run(ctx, []string{"wifi", "add", "--name-file", nameFile, "--password-file", addedSecret, "--copy-from-file", copyFile, "--socket", socket}, &output); err != nil {
		t.Fatal(err)
	}
	apVersion = decodePublicQueuedVersion(t, output.Bytes())
	apReport = acknowledgePublicResource(t, managed, apID, key, apReport, apVersion, false)

	wifiFile := filepath.Join(directory, "wifi.json")
	writeTypedJSON(t, wifiFile, network.WiFiNetwork{Name: "CLI Renamed", BSSTransition: network.Supplied(network.BSSTransitionDisabled)})
	output.Reset()
	if err := run(ctx, []string{"wifi", "set", "--current-name-file", currentFile, "--file", wifiFile, "--socket", socket}, &output); err != nil {
		t.Fatal(err)
	}
	apVersion = decodePublicQueuedVersion(t, output.Bytes())
	reply = typedExchange(t, managed, apID, key, apReport, false)
	assertPublicBSSPolicy(t, reply.SystemConfig, "Documentation", "CLI Renamed")
	apReport.ConfigVersion = string(apVersion)
	typedExchange(t, managed, apID, key, apReport, false)

	radioFile := filepath.Join(directory, "radio.json")
	writeTypedJSON(t, radioFile, network.RadioConfig{ID: "wifi0", Enabled: network.Supplied(true)})
	output.Reset()
	if err := run(ctx, []string{"radio", "set", "--file", radioFile, "--socket", socket}, &output); err != nil {
		t.Fatal(err)
	}
	apVersion = decodePublicQueuedVersion(t, output.Bytes())
	apReport = acknowledgePublicResource(t, managed, apID, key, apReport, apVersion, false)

	portFile := filepath.Join(directory, "port.json")
	writeTypedJSON(t, portFile, network.SwitchPortConfig{Index: 1, Enabled: network.Supplied(false)})
	output.Reset()
	if err := run(ctx, []string{"port", "set", "--file", portFile, "--socket", socket}, &output); err != nil {
		t.Fatal(err)
	}
	switchVersion = decodePublicQueuedVersion(t, output.Bytes())
	switchReport = acknowledgePublicResource(t, managed, switchID, key, switchReport, switchVersion, true)

	writeTypedFixture(t, nameFile, []byte("CLI Renamed\n"))
	output.Reset()
	if err := run(ctx, []string{"wifi", "remove", "--name-file", nameFile, "--socket", socket}, &output); err != nil {
		t.Fatal(err)
	}
	apVersion = decodePublicQueuedVersion(t, output.Bytes())
	acknowledgePublicResource(t, managed, apID, key, apReport, apVersion, false)
	assertPublicResourceOutputSafe(t, output.String(), key, sourceSecret, addedSecret, storedHash, string(sourceMaterial), string(destinationMaterial))

	assertPublicSelectorFailures(t, ctx, socket, directory, nameFile, copyFile, currentFile, addedSecret)
	assertPublicResourceDecodeFailures(t, ctx, socket, directory)
	assertPublicDeviceSelection(t, ctx, directory, key)
	assertPublicResourceExecutable(t, ctx, directory, socket, managed, apID, switchID, key, &apReport, &switchReport, sourceSecret, addedSecret, storedHash, string(sourceMaterial), string(destinationMaterial))
}

func acknowledgePublicResource(t *testing.T, managed *controller.Controller, id network.DeviceID, key string, report informmodel.Report, version network.ConfigVersion, gcm bool) informmodel.Report {
	t.Helper()
	reply := typedExchange(t, managed, id, key, report, gcm)
	if reply.Type != controller.ReplySetparam || reply.ConfigVersion != string(version) {
		t.Fatal("public resource mutation was not delivered")
	}
	report.ConfigVersion = string(version)
	if reply := typedExchange(t, managed, id, key, report, gcm); reply.Type != controller.ReplyNoop {
		t.Fatal("public resource acknowledgement received a command")
	}
	return report
}

func assertPublicBSSPolicy(t *testing.T, body, enabledName, disabledName string) {
	t.Helper()
	values, err := configmap.Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := profile.MatchRecord(values, "aaa.", "ssid", enabledName)
	if err != nil {
		t.Fatal("enabled WiFi authentication record is ambiguous")
	}
	disabled, err := profile.MatchRecord(values, "aaa.", "ssid", disabledName)
	if err != nil {
		t.Fatal("disabled WiFi authentication record is ambiguous")
	}
	if values[enabled+"bss_transition"] != "enabled" || values[disabled+"bss_transition"] != "disabled" {
		t.Fatal("per-network BSS Transition policy changed")
	}
}

func decodePublicQueuedVersion(t *testing.T, body []byte) network.ConfigVersion {
	t.Helper()
	var queued queuedVersion
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&queued); err != nil || queued.Version == "" {
		t.Fatal("resource command omitted queued version")
	}
	if decoder.Decode(new(json.RawMessage)) != io.EOF {
		t.Fatal("resource command returned trailing output")
	}
	return queued.Version
}

func assertPublicSelectorFailures(t *testing.T, ctx context.Context, socket, directory, nameFile, copyFile, currentFile, passwordFile string) {
	t.Helper()
	wifiFile := filepath.Join(directory, "selector-wifi.json")
	writeTypedJSON(t, wifiFile, network.WiFiNetwork{Name: "Selector"})
	cases := [][]string{
		{"wifi", "add", "--name", "literal", "--name-file", nameFile, "--password-file", passwordFile, "--copy-from-file", copyFile, "--socket", socket},
		{"wifi", "add", "--name=", "--name-file", nameFile, "--password-file", passwordFile, "--copy-from-file", copyFile, "--socket", socket},
		{"wifi", "add", "--name", "literal", "--name-file=", "--password-file", passwordFile, "--copy-from-file", copyFile, "--socket", socket},
		{"wifi", "add", "--name-file", nameFile, "--password-file", passwordFile, "--copy-from", "literal", "--copy-from-file", copyFile, "--socket", socket},
		{"wifi", "add", "--name-file", nameFile, "--password-file", passwordFile, "--copy-from=", "--copy-from-file", copyFile, "--socket", socket},
		{"wifi", "add", "--name-file", nameFile, "--password-file", passwordFile, "--copy-from", "literal", "--copy-from-file=", "--socket", socket},
		{"wifi", "set", "--current-name", "literal", "--current-name-file", currentFile, "--file", wifiFile, "--socket", socket},
		{"wifi", "set", "--current-name=", "--current-name-file", currentFile, "--file", wifiFile, "--socket", socket},
		{"wifi", "set", "--current-name", "literal", "--current-name-file=", "--file", wifiFile, "--socket", socket},
		{"wifi", "remove", "--name", "literal", "--name-file", nameFile, "--socket", socket},
		{"wifi", "remove", "--name=", "--name-file", nameFile, "--socket", socket},
		{"wifi", "remove", "--name", "literal", "--name-file=", "--socket", socket},
	}
	for _, arguments := range cases {
		if err := run(ctx, arguments, io.Discard); err == nil || !strings.Contains(err.Error(), "requires exactly one literal or file") {
			t.Fatal("conflicting resource selectors were accepted")
		}
	}
	multiline := filepath.Join(directory, "multiline")
	writeTypedFixture(t, multiline, []byte("first\nsecond\n"))
	if err := run(ctx, []string{"wifi", "remove", "--name-file", multiline, "--socket", socket}, io.Discard); err == nil {
		t.Fatal("multi-line selector was accepted")
	}
}

func assertPublicResourceDecodeFailures(t *testing.T, ctx context.Context, socket, directory string) {
	t.Helper()
	files := []struct {
		name string
		body string
		args []string
	}{
		{"wifi-unknown.json", `{"name":"Ignored","unexpected":true}`, []string{"wifi", "set", "--current-name", "Documentation"}},
		{"radio-trailing.json", `{"id":"wifi0"}{}`, []string{"radio", "set"}},
		{"port-unknown.json", `{"index":1,"unexpected":true}`, []string{"port", "set"}},
	}
	for _, test := range files {
		path := filepath.Join(directory, test.name)
		writeTypedFixture(t, path, []byte(test.body))
		arguments := append(test.args, "--file", path, "--socket", socket)
		if err := run(ctx, arguments, io.Discard); err == nil {
			t.Fatal("invalid resource JSON was accepted")
		}
	}
}

func assertPublicDeviceSelection(t *testing.T, ctx context.Context, directory, key string) {
	t.Helper()
	secondState := filepath.Join(directory, "ambiguous-state.json")
	writeTypedJSON(t, secondState, []controller.Device{
		{MAC: "02:00:00:00:03:11", Key: key, Family: network.FamilyAP},
		{MAC: "02:00:00:00:03:12", Key: key, Family: network.FamilyAP},
	})
	ambiguousSocket := startTypedSocket(t, openTypedController(t, secondState))
	err := run(ctx, []string{"wifi", "list", "--socket", ambiguousSocket}, io.Discard)
	assertControlFailure(t, err, network.AmbiguousDevice, "")

	emptyState := filepath.Join(directory, "empty-state.json")
	writeTypedJSON(t, emptyState, []controller.Device{{MAC: "02:00:00:00:03:13", Key: key, Family: network.FamilySwitch}})
	emptyController := openTypedController(t, emptyState)
	emptySocket := startTypedSocket(t, emptyController)
	err = run(ctx, []string{"wifi", "list", "--socket", emptySocket}, io.Discard)
	assertControlFailure(t, err, network.AmbiguousDevice, "")
	if emptyController.Status()[0].Pending != 0 {
		t.Fatal("zero-candidate selection issued a resource mutation")
	}
}

func assertPublicResourceExecutable(
	t *testing.T,
	ctx context.Context,
	directory string,
	socket string,
	managed *controller.Controller,
	apID network.DeviceID,
	switchID network.DeviceID,
	key string,
	apReport *informmodel.Report,
	switchReport *informmodel.Report,
	sourceSecret string,
	addedSecret string,
	storedHash string,
	sourceMaterial string,
	addedMaterial string,
) {
	t.Helper()
	binaryPath := filepath.Join(directory, "resource-unifi-go")
	if err := os.Remove(binaryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	buildStarted := time.Now()
	if output, err := exec.CommandContext(ctx, "go", "build", "-o", binaryPath, ".").CombinedOutput(); err != nil {
		t.Fatalf("build resource CLI: %v: %s", err, output)
	}
	info, err := os.Stat(binaryPath)
	if err != nil || info.ModTime().Before(buildStarted) {
		t.Fatal("resource CLI build did not produce a fresh executable")
	}
	forbidden := []string{key, sourceSecret, addedSecret, storedHash, sourceMaterial, addedMaterial}
	runSuccess := func(arguments ...string) []byte {
		t.Helper()
		output, commandErr := exec.CommandContext(ctx, binaryPath, arguments...).CombinedOutput()
		if commandErr != nil {
			t.Fatal("fresh resource executable failed")
		}
		assertPublicResourceOutputSafe(t, string(output), forbidden...)
		return output
	}
	runSuccess("wifi", "list", "--socket", socket)

	nameFile := filepath.Join(directory, "executable-name")
	copyFile := filepath.Join(directory, "executable-copy")
	currentFile := filepath.Join(directory, "executable-current")
	writeTypedFixture(t, nameFile, []byte("Executable Added\n"))
	writeTypedFixture(t, copyFile, []byte("Documentation\n"))
	writeTypedFixture(t, currentFile, []byte("Executable Added\n"))
	output := runSuccess("wifi", "add", "--name-file", nameFile, "--password-file", addedSecret, "--copy-from-file", copyFile, "--socket", socket)
	version := decodePublicQueuedVersion(t, output)
	*apReport = acknowledgePublicResource(t, managed, apID, key, *apReport, version, false)

	wifiFile := filepath.Join(directory, "executable-wifi.json")
	writeTypedJSON(t, wifiFile, network.WiFiNetwork{Name: "Executable Renamed", BSSTransition: network.Supplied(network.BSSTransitionDisabled)})
	output = runSuccess("wifi", "set", "--current-name-file", currentFile, "--file", wifiFile, "--socket", socket)
	version = decodePublicQueuedVersion(t, output)
	*apReport = acknowledgePublicResource(t, managed, apID, key, *apReport, version, false)

	radioFile := filepath.Join(directory, "executable-radio.json")
	writeTypedJSON(t, radioFile, network.RadioConfig{ID: "wifi0", Enabled: network.Supplied(false)})
	output = runSuccess("radio", "set", "--file", radioFile, "--socket", socket)
	version = decodePublicQueuedVersion(t, output)
	*apReport = acknowledgePublicResource(t, managed, apID, key, *apReport, version, false)

	portFile := filepath.Join(directory, "executable-port.json")
	writeTypedJSON(t, portFile, network.SwitchPortConfig{Index: 1, Enabled: network.Supplied(true)})
	output = runSuccess("port", "set", "--file", portFile, "--socket", socket)
	version = decodePublicQueuedVersion(t, output)
	*switchReport = acknowledgePublicResource(t, managed, switchID, key, *switchReport, version, true)

	writeTypedFixture(t, nameFile, []byte("Executable Renamed\n"))
	output = runSuccess("wifi", "remove", "--name-file", nameFile, "--socket", socket)
	version = decodePublicQueuedVersion(t, output)
	*apReport = acknowledgePublicResource(t, managed, apID, key, *apReport, version, false)

	beforePending := resourcePending(managed, apID)
	failureOutput, err := exec.CommandContext(ctx, binaryPath, "wifi", "remove", "--name=", "--name-file", nameFile, "--socket", socket).CombinedOutput()
	exitError, ok := errors.AsType[*exec.ExitError](err)
	if !ok || exitError.ExitCode() == 0 {
		t.Fatal("resource executable failure returned success")
	}
	assertPublicResourceOutputSafe(t, string(failureOutput), forbidden...)
	if resourcePending(managed, apID) != beforePending {
		t.Fatal("resource executable failure issued a mutation")
	}
}

func assertPublicResourceOutputSafe(t *testing.T, value any, forbidden ...string) {
	t.Helper()
	body, err := json.Marshal(value)
	if text, ok := value.(string); ok {
		body = []byte(text)
		err = nil
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range forbidden {
		if secret != "" && bytes.Contains(body, []byte(secret)) {
			t.Fatal("resource output exposed secret material")
		}
	}
}
