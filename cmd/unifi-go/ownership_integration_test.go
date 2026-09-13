package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"goodkind.io/unifi-go/internal/configmap"
	"goodkind.io/unifi-go/internal/controller"
	"goodkind.io/unifi-go/internal/informmodel"
	"goodkind.io/unifi-go/network"
)

func TestBaselineImportRejectsAmbiguousOwnership(t *testing.T) {
	for _, scenario := range []string{"shared filter", "unprojected shared filter", "duplicate bridge membership", "shared interface", "duplicate authentication", "duplicate interface record", "duplicate radio", "duplicate bridge"} {
		t.Run(scenario, func(t *testing.T) {
			config, baseline := typedBSSFixture(t, "unused-fixture-secret", "imported")
			values, err := configmap.Parse(baseline.Config.System)
			if err != nil {
				t.Fatal("cannot parse ownership fixture")
			}
			switch scenario {
			case "shared filter", "unprojected shared filter":
				values["ebtables.99.cmd"] = "-A FORWARD --in-interface ath0 --out-interface ath2 -j ACCEPT"
				if scenario == "unprojected shared filter" {
					config.Networks.Value = config.Networks.Value[:1]
				}
			case "duplicate bridge membership":
				values["bridge.2.devname"] = "br-operator"
				values["bridge.2.port.1.devname"] = "ath0"
			case "shared interface":
				values["wireless.2.devname"] = "ath0"
				for key := range values {
					if strings.HasPrefix(key, "aaa.2.") {
						delete(values, key)
					}
				}
			case "duplicate authentication":
				values["aaa.99.ssid"], values["aaa.99.devname"] = "fixture-legacy", "ath0"
			case "duplicate interface record":
				values["netconf.99.devname"] = "ath0"
			case "duplicate radio":
				values["radio.99.phyname"] = "wifi0"
			case "duplicate bridge":
				values["bridge.99.devname"] = "br0"
			}
			baseline.Config.System, err = values.Encode()
			if err != nil {
				t.Fatal("cannot encode ownership fixture")
			}
			state := filepath.Join(t.TempDir(), "state.json")
			writeTypedJSON(t, state, []controller.Device{{MAC: string(previewTestID), Key: previewTestKey}})
			c := openTypedController(t, state)
			client := network.Dial(startTypedSocket(t, c))
			report := informmodel.Report{Type: "uap", RadioTable: []informmodel.Radio{{Name: "wifi0", Radio: "ng"}, {Name: "wifi1", Radio: "na"}}}
			typedExchange(t, c, previewTestID, previewTestKey, report, true)
			before := previewStateBytes(t, state)
			err = client.ImportBaseline(t.Context(), previewTestID, network.BaselineImport{Config: baseline.Config, AP: &config})
			assertControlFailure(t, err, network.BaselineUnusable, "")
			if !bytes.Equal(before, previewStateBytes(t, state)) || c.Status()[0].Pending != 0 {
				t.Fatal("ambiguous ownership import changed state or queued work")
			}
		})
	}
}

func TestBaselineImportAcceptsStableRadioIDs(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef" // gitleaks:allow
	const id network.DeviceID = "02:00:00:00:04:11"
	directory := t.TempDir()
	state := filepath.Join(directory, "state.json")
	writeTypedJSON(t, state, []controller.Device{{MAC: string(id), Key: key}})
	managed := openTypedController(t, state)
	client := network.Dial(startTypedSocket(t, managed))
	report := informmodel.Report{
		Type: "uap", Model: "StableRadioAP", Version: "1",
		RadioTable: []informmodel.Radio{{Name: "wifi0", Radio: "ng"}, {Name: "wifi1", Radio: "na"}},
		PortTable:  []informmodel.Port{{Index: 1, Interface: "eth0"}},
	}
	typedExchange(t, managed, id, key, report, false)

	config, baseline := typedBSSFixture(t, filepath.Join(directory, "unused-secret"), "stable-radio-baseline")
	config.Radios.Value[0].ID = "wifi0"
	config.Radios.Value[1].ID = "wifi1"
	for index := range config.Networks.Value {
		config.Networks.Value[index].Bands = network.Optional[[]network.RadioBand]{}
		config.Networks.Value[index].RadioIDs = network.Supplied([]network.RadioID{"wifi0"})
	}
	config.Networks.Value[0].RadioIDs = network.Supplied([]network.RadioID{"wifi0", "wifi1"})
	if err := client.ImportBaseline(t.Context(), id, network.BaselineImport{Config: baseline.Config, AP: &config}); err != nil {
		t.Fatal("stable radio identity baseline import failed", err)
	}
	networks, err := client.WiFiNetworks(t.Context(), id)
	if err != nil || len(networks) != 4 || len(networks[0].RadioIDs) == 0 {
		t.Fatal("stable radio identity did not survive baseline import")
	}
}

func TestFailedRawReplacementPreservesTypedAcknowledgement(t *testing.T) {
	fixture := newPreviewFixture(t)
	version, err := fixture.client.ApplyAP(t.Context(), previewTestID, fixture.config)
	if err != nil {
		t.Fatal("cannot establish typed pending configuration")
	}
	typedExchange(t, fixture.controller, previewTestID, previewTestKey, fixture.report, true)
	before := previewStateBytes(t, fixture.state)
	saved := fixture.state + ".saved"
	if err := os.Rename(fixture.state, saved); err != nil {
		t.Fatal("cannot preserve fixture state")
	}
	if err := os.Mkdir(fixture.state, 0o700); err != nil {
		t.Fatal("cannot block fixture state replacement")
	}
	raw := network.Config{Version: "replacement", Management: "a=b\n", System: "c=d\n"}
	_, err = fixture.client.ApplyConfig(t.Context(), previewTestID, raw)
	assertControlFailure(t, err, network.PersistenceFailed, "")
	if err := os.Remove(fixture.state); err != nil {
		t.Fatal("cannot unblock fixture state")
	}
	if err := os.Rename(saved, fixture.state); err != nil {
		t.Fatal("cannot restore fixture state")
	}
	if !bytes.Equal(before, previewStateBytes(t, fixture.state)) || fixture.controller.Status()[0].Pending != 0 {
		t.Fatal("failed raw replacement changed persisted state or queue")
	}
	_, err = fixture.client.PreviewAP(t.Context(), previewTestID, network.APConfig{})
	assertControlFailure(t, err, network.ConfigurationPending, "")
	fixture.report.ConfigVersion = string(version)
	typedExchange(t, fixture.controller, previewTestID, previewTestKey, fixture.report, true)
	if _, err := fixture.client.PreviewAP(t.Context(), previewTestID, network.APConfig{}); err != nil {
		t.Fatal("original acknowledgement did not release the pending transaction")
	}
}

func TestRawReplacementClearsSupersededTypedAcknowledgement(t *testing.T) {
	fixture := newPreviewFixture(t)
	if _, err := fixture.client.ApplyAP(t.Context(), previewTestID, fixture.config); err != nil {
		t.Fatal("cannot establish typed pending configuration")
	}
	if reply := typedExchange(t, fixture.controller, previewTestID, previewTestKey, fixture.report, true); reply.Type != controller.ReplySetparam {
		t.Fatal("typed configuration was not delivered")
	}
	device := previewPersistedDevice(t, fixture.state)
	raw := device.Baseline.Config
	raw.Version = "operator-replacement"
	management, err := configmap.Parse(raw.Management)
	if err != nil {
		t.Fatal("cannot parse management fixture")
	}
	management["cfgversion"] = string(raw.Version)
	raw.Management, err = management.Encode()
	if err != nil {
		t.Fatal("cannot encode management fixture")
	}
	if _, err := fixture.client.ApplyConfig(t.Context(), previewTestID, raw); err != nil {
		t.Fatal("raw replacement failed")
	}
	if reply := typedExchange(t, fixture.controller, previewTestID, previewTestKey, fixture.report, true); reply.ConfigVersion != string(raw.Version) {
		t.Fatal("raw replacement was not delivered")
	}
	fixture.report.ConfigVersion = string(raw.Version)
	typedExchange(t, fixture.controller, previewTestID, previewTestKey, fixture.report, true)
	if err := fixture.client.ImportBaseline(t.Context(), previewTestID, network.BaselineImport{Config: raw, AP: device.DesiredAP}); err != nil {
		t.Fatal("raw reconciliation failed")
	}
	request := network.APConfig{CountryCode: network.Supplied(uint16(124))}
	preview, err := fixture.client.PreviewAP(t.Context(), previewTestID, request)
	if err != nil {
		t.Fatal("superseded typed acknowledgement blocked reconciled preview")
	}
	if _, err := fixture.client.ApplyAPPreview(t.Context(), previewTestID, request, preview.Token); err != nil {
		t.Fatal("superseded typed acknowledgement blocked reconciled apply")
	}
	if fixture.controller.Status()[0].Pending != 1 {
		t.Fatal("reconciled typed apply did not queue one reply")
	}
}

func TestWiFiListResolvesIdentityOnlyBaselinePolicy(t *testing.T) {
	_, baseline := typedBSSFixture(t, "unused-fixture-secret", "imported")
	values, err := configmap.Parse(baseline.Config.System)
	if err != nil {
		t.Fatal(err)
	}
	values["bridge.2.devname"] = "br0.20"
	values["bridge.2.port.1.devname"], values["bridge.2.port.2.devname"] = "ath0", "ath1"
	delete(values, "bridge.1.port.10.devname")
	delete(values, "bridge.1.port.20.devname")
	values["aaa.1.br.devname"], values["aaa.2.br.devname"] = "br0.20", "br0.20"
	baseline.Config.System, err = values.Encode()
	if err != nil {
		t.Fatal(err)
	}
	projection := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{{
		Name: "fixture-legacy", Bands: network.Supplied([]network.RadioBand{network.Band2GHz, network.Band5GHz}),
	}})}
	views := importIdentityOnlyWiFiList(t, baseline, projection)
	if !views[0].Enabled.Present || !views[0].Enabled.Value || !views[0].VLAN.Present || views[0].VLAN.Null || views[0].VLAN.Value != 20 || !views[0].SecurityMode.Present || views[0].SecurityMode.Value != network.WPA2Personal {
		t.Fatalf("safe WiFi list lost bound baseline policy: enabled=%+v vlan=%+v security=%+v", views[0].Enabled, views[0].VLAN, views[0].SecurityMode)
	}

	unknown := *baseline
	unknownValues := values.Clone()
	unknownValues["bridge.2.devname"] = "operator-bridge"
	for _, index := range []string{"1", "2"} {
		delete(unknownValues, "wireless."+index+".status")
		delete(unknownValues, "aaa."+index+".status")
		unknownValues["aaa."+index+".br.devname"] = "operator-bridge"
		delete(unknownValues, "aaa."+index+".wpa")
		delete(unknownValues, "aaa."+index+".wpa.1.pairwise")
		delete(unknownValues, "aaa."+index+".wpa.key.1.mgmt")
	}
	unknown.Config.System, err = unknownValues.Encode()
	if err != nil {
		t.Fatal(err)
	}
	views = importIdentityOnlyWiFiList(t, &unknown, projection)
	if views[0].Enabled.Present || views[0].VLAN.Present || views[0].SecurityMode.Present {
		t.Fatal("unknown bound policy acquired concrete values")
	}
}

func importIdentityOnlyWiFiList(t *testing.T, baseline *controller.ConfigurationBaseline, projection network.APConfig) []network.WiFiNetworkView {
	t.Helper()
	state := filepath.Join(t.TempDir(), "state.json")
	writeTypedJSON(t, state, []controller.Device{{MAC: string(previewTestID), Key: previewTestKey}})
	managed := openTypedController(t, state)
	client := network.Dial(startTypedSocket(t, managed))
	report := informmodel.Report{Type: "uap", RadioTable: []informmodel.Radio{{Name: "wifi0", Radio: "ng"}, {Name: "wifi1", Radio: "na"}}}
	typedExchange(t, managed, previewTestID, previewTestKey, report, true)
	if err := client.ImportBaseline(t.Context(), previewTestID, network.BaselineImport{Config: baseline.Config, AP: &projection}); err != nil {
		t.Fatal("identity-only import failed", err)
	}
	views, err := client.WiFiNetworks(t.Context(), previewTestID)
	if err != nil || len(views) != 1 {
		t.Fatal("WiFi list failed", err)
	}
	return views
}
