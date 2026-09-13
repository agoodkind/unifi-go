package integration_test

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"goodkind.io/unifi-go/internal/configmap"
	"goodkind.io/unifi-go/internal/informmodel"
	"goodkind.io/unifi-go/internal/profile"
	"goodkind.io/unifi-go/internal/profile/ap"
	"goodkind.io/unifi-go/network"
)

type fileSecrets struct{}

func (fileSecrets) ReadSecret(path network.SecretFile) ([]byte, error) {
	return os.ReadFile(string(path))
}

func compilerFixture(t *testing.T, family, name string) profile.SetParam {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "testdata", "profiles", family, name))
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
	return profile.SetParam{Management: fixture.Management, System: fixture.System}
}

func assertComposition(t *testing.T, actual profile.SetParam, management, system configmap.Values) {
	t.Helper()
	if !maps.Equal(actual.Management, management) || !maps.Equal(actual.System, system) {
		t.Fatal("complete composed maps differ from requested changes")
	}
	if actual.Version == "" {
		t.Fatal("configuration version is missing")
	}
}

func TestAPCompilerFromNetworkServerFixture(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "testdata", "profiles", "ap", "operation-01-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report informmodel.Report
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	report.SystemConfig, report.ManagementConfig = true, true
	report.PacketVersion, report.PayloadVersion = 1, 1
	descriptor, err := profile.DescribeWithFamily(report, network.FamilyAP)
	if err != nil {
		t.Fatal(err)
	}
	baseline := compilerFixture(t, "ap", "operation-05-reply.json")
	baseline.System["locale.timezone"] = "operator-zone"
	baseline.System["operator.unmodeled"] = "retain"
	baseline.System["sshd.status"] = "disabled"
	baseline.Management["operator.unmodeled"] = "retain-management"
	// Split the captured WLAN and add one named synthetic WLAN with distinct retained policy.
	baseline.System["wireless.2.ssid"], baseline.System["aaa.2.ssid"] = "legacy", "legacy"
	baseline.System["aaa.1.bss_transition"], baseline.System["aaa.2.bss_transition"] = "enabled", "disabled"
	for key, value := range baseline.System.Clone() {
		for _, pair := range [][2]string{{"wireless.2.", "wireless.3."}, {"aaa.2.", "aaa.3."}, {"netconf.4.", "netconf.7."}} {
			if len(key) >= len(pair[0]) && key[:len(pair[0])] == pair[0] {
				baseline.System[pair[1]+key[len(pair[0]):]] = value
			}
		}
	}
	baseline.System["wireless.3.ssid"], baseline.System["aaa.3.ssid"] = "guest", "guest"
	baseline.System["wireless.3.devname"], baseline.System["aaa.3.devname"], baseline.System["netconf.7.devname"] = "ath2", "ath2", "ath2"
	baseline.System["bridge.2.port.4.devname"] = "ath2"
	delete(baseline.System, "aaa.3.bss_transition")
	baseline.System["wireless.2.operator.unmodeled"] = "legacy-only"
	baseline.System["aaa.2.wpa.key.1.mgmt"] = "UNSUPPORTED-UNCHANGED"
	config := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{
		{Name: "fixture-wifi", Bands: network.Supplied([]network.RadioBand{network.Band5GHz})},
		{Name: "legacy", Bands: network.Supplied([]network.RadioBand{network.Band2GHz})},
		{Name: "guest", Bands: network.Supplied([]network.RadioBand{network.Band2GHz})},
	})}
	input := profile.CompilationInput{Baseline: baseline, AP: &config}
	registry := profile.NewRegistry(ap.New(), nil)
	request := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{
		{Name: "guest"}, {Name: "legacy", Enabled: network.Supplied(false)}, {Name: "fixture-wifi"},
	})}
	before := baseline.System.Clone()
	compiled, err := registry.CompileAP(descriptor, input, request, nil)
	if err != nil {
		t.Fatal("baseline composition failed", err)
	}
	expected := before.Clone()
	expected["wireless.2.status"], expected["aaa.2.status"] = "disabled", "disabled"
	assertComposition(t, compiled.Param, baseline.Management, expected)
	if !maps.Equal(before, baseline.System) || config.Networks.Value[1].Enabled.Present {
		t.Fatal("compilation mutated input")
	}
	if compiled.AP == nil || compiled.Switch != nil || len(compiled.Bindings) != 3 {
		t.Fatal("projection or bindings are incomplete")
	}
	repeated, err := registry.CompileAP(descriptor, profile.CompilationInput{Baseline: compiled.Param, AP: compiled.AP, Bindings: compiled.Bindings}, request, nil)
	if err != nil || repeated.Param.Version != compiled.Param.Version || !reflect.DeepEqual(repeated.Bindings, compiled.Bindings) {
		t.Fatal("repeated overlay changed stable identity")
	}
	changedInput := input
	changedInput.Baseline.System = baseline.System.Clone()
	changedInput.Baseline.System["operator.unmodeled"] = "changed"
	changed, err := registry.CompileAP(descriptor, changedInput, request, nil)
	if err != nil || changed.Param.Version == compiled.Param.Version {
		t.Fatal("unknown retained policy was excluded from version")
	}
	t.Run("omitted collections", func(t *testing.T) {
		result, err := registry.CompileAP(descriptor, input, network.APConfig{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		assertComposition(t, result.Param, baseline.Management, before)
	})
	t.Run("clear VLAN and channel", func(t *testing.T) {
		req := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{{Name: "fixture-wifi"}, {Name: "legacy", VLAN: network.Cleared[network.VLANID]()}, {Name: "guest"}}), Radios: network.Supplied([]network.RadioConfig{{Band: network.Band2GHz, Channel: network.Cleared[uint16]()}})}
		result, err := registry.CompileAP(descriptor, input, req, nil)
		if err != nil {
			t.Fatal(err)
		}
		want := before.Clone()
		want["aaa.2.br.devname"] = "br0"
		want["radio.2.channel"] = "auto"
		delete(want, "bridge.2.port.2.devname")
		want["bridge.1.port.2.devname"] = "ath1"
		assertComposition(t, result.Param, baseline.Management, want)
	})
	t.Run("remove typed members only", func(t *testing.T) {
		result, err := registry.CompileAP(descriptor, input, network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{})}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if result.Param.System["operator.unmodeled"] != "retain" || result.Param.System["wireless.2.operator.unmodeled"] != "" || result.Param.System["wireless.1.ssid"] != "" || result.Param.System["radio.1.phyname"] == "" {
			t.Fatal("resource removal lost ownership boundaries")
		}
	})
	t.Run("ambiguous identity", func(t *testing.T) {
		bad := input
		bad.Baseline.System = before.Clone()
		bad.Baseline.System["wireless.4.ssid"], bad.Baseline.System["wireless.4.parent"], bad.Baseline.System["wireless.4.devname"] = "legacy", "wifi-ng", "ath9"
		if _, err := registry.CompileAP(descriptor, bad, request, nil); err == nil {
			t.Fatal("duplicate identity was accepted")
		}
	})
	t.Run("capabilities apply only to requested setting", func(t *testing.T) {
		unfamiliar := descriptor
		unfamiliar.Model, unfamiliar.Firmware = "UNRECOGNIZED", "1"
		result, err := registry.CompileAP(unfamiliar, input, request, nil)
		if err != nil {
			t.Fatal("unrecognized model rejected unchanged capability policy")
		}
		assertComposition(t, result.Param, baseline.Management, expected)
		req := network.APConfig{Radios: network.Supplied([]network.RadioConfig{{Band: network.Band2GHz, Channel: network.Supplied(uint16(6))}})}
		if _, err := registry.CompileAP(unfamiliar, input, req, nil); err == nil {
			t.Fatal("missing channel evidence accepted")
		}
		unfamiliar.Radios = append([]profile.RadioCapability(nil), descriptor.Radios...)
		for index := range unfamiliar.Radios {
			unfamiliar.Radios[index].Channels = []uint16{6}
		}
		if _, err := registry.CompileAP(unfamiliar, input, req, nil); err != nil {
			t.Fatal("reported channel rejected", err)
		}
	})
	t.Run("new WLAN requires policy", func(t *testing.T) {
		req := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{{Name: "new"}})}
		if _, err := registry.CompileAP(descriptor, input, req, nil); err == nil {
			t.Fatal("new resource used hidden policy")
		}
	})

	t.Run("add explicit WLAN", func(t *testing.T) {
		secretPath := filepath.Join(t.TempDir(), "psk")
		if err := os.WriteFile(secretPath, []byte("fixture-passphrase"), 0o600); err != nil {
			t.Fatal(err)
		}
		newWiFi := network.WiFiNetwork{Name: "new", Enabled: network.Supplied(true), VLAN: network.Cleared[network.VLANID](), Bands: network.Supplied([]network.RadioBand{network.Band2GHz}), BSSTransition: network.Supplied(network.BSSTransitionDisabled), Security: network.Supplied(network.WiFiSecurity{Mode: network.Supplied(network.WPA2Personal), PSK: network.Supplied(network.SecretFile(secretPath))})}
		req := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{{Name: "guest"}, {Name: "legacy"}, {Name: "fixture-wifi"}, newWiFi})}
		result, err := registry.CompileAP(descriptor, input, req, fileSecrets{})
		if err != nil {
			t.Fatal(err)
		}
		for key, value := range before {
			if result.Param.System[key] != value {
				t.Fatal("addition changed retained record")
			}
		}
		if result.Param.System["wireless.4.ssid"] != "new" || result.Param.System["aaa.4.bss_transition"] != "disabled" || result.Param.System["aaa.4.wpa.psk"] != "fixture-passphrase" {
			t.Fatal("new explicit policy is missing")
		}
		if _, exists := result.Param.System["wireless.4.dtim_period"]; exists {
			t.Fatal("new WLAN selected omitted rate policy")
		}
	})
	t.Run("band addition copies owned unknown records", func(t *testing.T) {
		copyInput := input
		copyInput.Baseline.System = before.Clone()
		copyInput.Baseline.System["netconf.4.operator.unmodeled"] = "copy-interface"
		copyInput.Baseline.System["bridge.2.port.2.operator.unmodeled"] = "copy-member"
		copyInput.Baseline.System["ebtables.99.cmd"] = "-t nat -A PREROUTING --in-interface ath1 -j DROP"
		copyInput.Baseline.System["ebtables.99.operator.unmodeled"] = "copy-filter"
		req := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{{Name: "guest"}, {Name: "legacy", Bands: network.Supplied([]network.RadioBand{network.Band2GHz, network.Band5GHz})}, {Name: "fixture-wifi"}})}
		result, err := registry.CompileAP(descriptor, copyInput, req, nil)
		if err != nil {
			t.Fatal(err)
		}
		for key, value := range copyInput.Baseline.System {
			if result.Param.System[key] != value {
				t.Fatal("band addition changed retained record")
			}
		}
		var target profile.ResourceBinding
		for _, binding := range result.Bindings {
			if binding.Kind == "wifi" && binding.Identity == "legacy" && binding.Prefixes[0] != "wireless.2." {
				target = binding
			}
		}
		if len(target.Prefixes) < 4 {
			t.Fatal("band copy omitted owned references")
		}
		if result.Param.System[target.Prefixes[0]+"operator.unmodeled"] != "legacy-only" || result.Param.System[target.Prefixes[1]+"wpa.key.1.mgmt"] != "UNSUPPORTED-UNCHANGED" {
			t.Fatal("band copy lost untyped WLAN policy")
		}
		copied := map[string]bool{}
		for _, prefix := range target.Prefixes {
			if value := result.Param.System[prefix+"operator.unmodeled"]; value != "" {
				copied[value] = true
			}
		}
		if !copied["copy-interface"] || !copied["copy-member"] || !copied["copy-filter"] {
			t.Fatal("band copy lost unknown owned records")
		}
	})
	t.Run("partial SSH preserves service policy", func(t *testing.T) {
		result, err := registry.CompileAP(descriptor, input, network.APConfig{SSH: network.Supplied(network.SSHConfig{Username: network.Supplied("renamed")})}, nil)
		if err != nil {
			t.Fatal(err)
		}
		want := before.Clone()
		want["users.1.name"] = "renamed"
		assertComposition(t, result.Param, baseline.Management, want)
	})

	t.Run("VLAN move retains unknown membership policy", func(t *testing.T) {
		moved := input
		moved.Baseline.System = before.Clone()
		moved.Baseline.System["bridge.2.port.2.operator.unmodeled"] = "retain-member"
		req := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{{Name: "fixture-wifi"}, {Name: "legacy", VLAN: network.Cleared[network.VLANID]()}, {Name: "guest"}})}
		result, err := registry.CompileAP(descriptor, moved, req, nil)
		if err != nil {
			t.Fatal(err)
		}
		if result.Param.System["bridge.1.port.2.operator.unmodeled"] != "retain-member" {
			t.Fatal("VLAN move lost unknown member policy")
		}
	})
	t.Run("move WLAN between radios", func(t *testing.T) {
		req := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{{Name: "fixture-wifi"}, {Name: "legacy", Bands: network.Supplied([]network.RadioBand{network.Band5GHz})}, {Name: "guest"}})}
		result, err := registry.CompileAP(descriptor, input, req, nil)
		if err != nil {
			t.Fatal(err)
		}
		if result.Param.System["wireless.2.ssid"] != "" || result.Param.System["wireless.4.operator.unmodeled"] != "legacy-only" || result.Param.System["wireless.4.parent"] != "wifi-na" {
			t.Fatal("radio move lost identity or unknown records")
		}
	})
	t.Run("result owns nested slices", func(t *testing.T) {
		result, err := registry.CompileAP(descriptor, input, network.APConfig{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		result.AP.Networks.Value[0].Bands.Value[0] = network.Band2GHz
		result.Bindings[0].Prefixes[0] = "changed"
		result.Param.Management["operator.unmodeled"] = "changed"
		if config.Networks.Value[0].Bands.Value[0] != network.Band5GHz || baseline.Management["operator.unmodeled"] != "retain-management" {
			t.Fatal("result aliases nested input")
		}
	})
	snapshot, err := ap.New().Decode(report)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Radios) != 2 || snapshot.Radios[0].Channel == nil || *snapshot.Radios[0].Channel != 1 {
		t.Fatal("decoded radio state is incorrect")
	}
	if snapshot.Radios[0].ClientCount == nil || *snapshot.Radios[0].ClientCount != 0 {
		t.Fatal("measured zero radio client count was lost")
	}
	var optionalReport informmodel.Report
	if err := json.Unmarshal([]byte(`{"vap_table":[{"essid":"fixture","radio":"ng","sta_table":[{"mac":"02:00:00:00:00:01"},{"mac":"02:00:00:00:00:02","rx_bytes":0,"tx_bytes":0}]}]}`), &optionalReport); err != nil {
		t.Fatal(err)
	}
	optionalSnapshot, err := ap.New().Decode(optionalReport)
	if err != nil {
		t.Fatal(err)
	}
	if optionalSnapshot.Clients[0].RxBytes != nil || optionalSnapshot.Clients[1].RxBytes == nil || *optionalSnapshot.Clients[1].RxBytes != 0 {
		t.Fatal("absent and zero client byte measurements were collapsed")
	}
	var physicalReport informmodel.Report
	if err := json.Unmarshal([]byte(`{"radio_table":[{"name":"wifi0","radio":"ng"},{"name":"wifi1","radio":"na"}],"vap_table":[{"radio":"ng","radio_name":"wifi0","channel":6,"bw":"20","tx_power":10,"num_sta":0},{"radio":"na","radio_name":"wifi1","channel":44,"bw":40,"tx_power":12}]} `), &physicalReport); err != nil {
		t.Fatal(err)
	}
	physicalSnapshot, err := ap.New().Decode(physicalReport)
	if err != nil {
		t.Fatal(err)
	}
	if physicalSnapshot.Radios[0].Channel == nil || *physicalSnapshot.Radios[0].Channel != 6 || physicalSnapshot.Radios[0].WidthMHz == nil || *physicalSnapshot.Radios[0].WidthMHz != network.Width20 || physicalSnapshot.Radios[0].PowerDBm == nil || *physicalSnapshot.Radios[0].PowerDBm != 10 {
		t.Fatal("physical VAP observations did not fill absent radio measurements")
	}
	if physicalSnapshot.Radios[0].ClientCount == nil || *physicalSnapshot.Radios[0].ClientCount != 0 || physicalSnapshot.Radios[1].ClientCount != nil {
		t.Fatal("physical VAP client counts lost absent versus zero")
	}
	var unidentifiedReport informmodel.Report
	if err := json.Unmarshal([]byte(`{"radio_table":[{"name":"wifi0"}],"vap_table":[{"radio_name":"wifi1","channel":44,"num_sta":2},{"channel":6,"num_sta":1}]}`), &unidentifiedReport); err != nil {
		t.Fatal(err)
	}
	unidentifiedSnapshot, err := ap.New().Decode(unidentifiedReport)
	if err != nil {
		t.Fatal(err)
	}
	if unidentifiedSnapshot.Radios[0].Channel != nil || unidentifiedSnapshot.Radios[0].ClientCount != nil {
		t.Fatal("unidentified radio absorbed unrelated VAP observations")
	}
}
