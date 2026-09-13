package integration_test

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
	}), Radios: network.Supplied([]network.RadioConfig{{Band: network.Band2GHz}, {Band: network.Band5GHz}})}
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
	for _, binding := range compiled.Bindings {
		if binding.Kind != "wifi" {
			continue
		}
		key := binding.Prefixes[1] + "bss_transition"
		if binding.Identity == "legacy" && compiled.Param.System[key] != before[key] {
			t.Fatal("disabled peer BSS Transition changed")
		}
		if binding.Identity == "guest" {
			if _, exists := compiled.Param.System[key]; exists {
				t.Fatal("omitted BSS Transition acquired a default")
			}
		}
	}
	assertComposition(t, compiled.Param, baseline.Management, expected)
	if !maps.Equal(before, baseline.System) || config.Networks.Value[1].Enabled.Present {
		t.Fatal("compilation mutated input")
	}
	if compiled.AP == nil || compiled.Switch != nil || len(compiled.Bindings) != 5 {
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
	t.Run("existing network enable inherits its selector", func(t *testing.T) {
		result, err := registry.CompileAP(descriptor, input, network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{
			{Name: "fixture-wifi"},
			{Name: "legacy", Enabled: network.Supplied(true)},
			{Name: "guest"},
		})}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if result.Param.System["wireless.2.status"] != "enabled" || result.Param.System["aaa.2.status"] != "enabled" {
			t.Fatal("partial network update did not inherit its baseline selector")
		}
	})
	t.Run("network selector replacement remains exclusive", func(t *testing.T) {
		byID, err := registry.CompileAP(descriptor, input, network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{
			{Name: "fixture-wifi"},
			{Name: "legacy", RadioIDs: network.Supplied([]network.RadioID{"wifi-ng"})},
			{Name: "guest"},
		})}, nil)
		if err != nil {
			t.Fatal(err)
		}
		legacy := byID.AP.Networks.Value[1]
		if legacy.Bands.Present || !reflect.DeepEqual(legacy.RadioIDs.Value, []network.RadioID{"wifi-ng"}) {
			t.Fatal("radio ID selector did not replace the inherited band selector")
		}

		byBand, err := registry.CompileAP(descriptor, profile.CompilationInput{
			Baseline: byID.Param,
			AP:       byID.AP,
			Bindings: byID.Bindings,
		}, network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{
			{Name: "fixture-wifi"},
			{Name: "legacy", Bands: network.Supplied([]network.RadioBand{network.Band2GHz})},
			{Name: "guest"},
		})}, nil)
		if err != nil {
			t.Fatal(err)
		}
		legacy = byBand.AP.Networks.Value[1]
		if legacy.RadioIDs.Present || !reflect.DeepEqual(legacy.Bands.Value, []network.RadioBand{network.Band2GHz}) {
			t.Fatal("band selector did not replace the inherited radio ID selector")
		}
	})
	t.Run("every requested band must resolve", func(t *testing.T) {
		singleBand := descriptor
		singleBand.Radios = []profile.RadioCapability{descriptor.Radios[0]}
		configured := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{
			{Name: "legacy", Bands: network.Supplied([]network.RadioBand{network.Band2GHz})},
			{Name: "guest", Bands: network.Supplied([]network.RadioBand{network.Band2GHz})},
		})}
		_, err := registry.CompileAP(singleBand, profile.CompilationInput{Baseline: baseline, AP: &configured}, network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{
			{Name: "legacy", Bands: network.Supplied([]network.RadioBand{network.Band2GHz, network.Band5GHz})},
			{Name: "guest"},
		})}, nil)
		if err == nil {
			t.Fatal("network selector accepted a band absent from reported inventory")
		}
	})
	t.Run("legacy projection radio policy survives partial update", func(t *testing.T) {
		legacy := config.Clone()
		legacy.Radios.Value[0] = network.RadioConfig{
			Band: network.Band2GHz, Enabled: network.Supplied(true), Channel: network.Cleared[uint16](),
			WidthMHz: network.Supplied(network.Width20), Power: network.Supplied(network.PowerConfig{Mode: network.Supplied(network.PowerAuto)}),
		}
		legacy.Radios.Value[1] = network.RadioConfig{
			Band: network.Band5GHz, Enabled: network.Supplied(true), Channel: network.Supplied(uint16(36)),
			WidthMHz: network.Supplied(network.Width40), Power: network.Supplied(network.PowerConfig{Mode: network.Supplied(network.PowerExplicit), DBm: network.Supplied(18)}),
		}
		result, err := registry.CompileAP(descriptor, profile.CompilationInput{Baseline: baseline, AP: &legacy}, network.APConfig{Radios: network.Supplied([]network.RadioConfig{
			{Band: network.Band2GHz, Enabled: network.Supplied(false)},
			{Band: network.Band5GHz},
		})}, nil)
		if err != nil {
			t.Fatal(err)
		}
		gotTwo, gotFive := result.AP.Radios.Value[0], result.AP.Radios.Value[1]
		if gotTwo.ID != "wifi-ng" || gotTwo.Enabled.Value || !gotTwo.Enabled.Present || !gotTwo.Channel.Null || gotTwo.WidthMHz.Value != network.Width20 || gotTwo.Power.Value.Mode.Value != network.PowerAuto {
			t.Fatal("partial radio update lost legacy 2.4 GHz policy")
		}
		if gotFive.ID != "wifi-na" || !gotFive.Enabled.Value || gotFive.Channel.Value != 36 || gotFive.WidthMHz.Value != network.Width40 || gotFive.Power.Value.Mode.Value != network.PowerExplicit || gotFive.Power.Value.DBm.Value != 18 {
			t.Fatal("partial radio update lost legacy 5 GHz policy")
		}
	})
	t.Run("BSS transition changes only the selected WLAN", func(t *testing.T) {
		bssBaseline := profile.SetParam{Management: baseline.Management.Clone(), System: before.Clone()}
		copyRecord := func(source, target string) {
			for key, value := range bssBaseline.System.Clone() {
				if strings.HasPrefix(key, source) {
					bssBaseline.System[target+strings.TrimPrefix(key, source)] = value
				}
			}
		}
		copyRecord("wireless.1.", "wireless.4.")
		copyRecord("aaa.1.", "aaa.4.")
		copyRecord("netconf.3.", "netconf.8.")
		bssBaseline.System["wireless.4.ssid"], bssBaseline.System["aaa.4.ssid"] = "legacy", "legacy"
		bssBaseline.System["wireless.4.devname"], bssBaseline.System["aaa.4.devname"], bssBaseline.System["netconf.8.devname"] = "ath3", "ath3", "ath3"
		bssBaseline.System["bridge.2.port.5.devname"] = "ath3"
		copyRecord("wireless.3.", "wireless.5.")
		copyRecord("aaa.3.", "aaa.5.")
		copyRecord("netconf.7.", "netconf.9.")
		bssBaseline.System["wireless.5.ssid"], bssBaseline.System["aaa.5.ssid"] = "disabled-peer", "disabled-peer"
		bssBaseline.System["wireless.5.devname"], bssBaseline.System["aaa.5.devname"], bssBaseline.System["netconf.9.devname"] = "ath4", "ath4", "ath4"
		bssBaseline.System["bridge.2.port.6.devname"] = "ath4"
		bssBaseline.System["aaa.2.bss_transition"], bssBaseline.System["aaa.4.bss_transition"] = "enabled", "enabled"
		bssBaseline.System["aaa.5.bss_transition"] = "disabled"

		bssConfig := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{
			{Name: "fixture-wifi", Bands: network.Supplied([]network.RadioBand{network.Band5GHz})},
			{Name: "legacy", Bands: network.Supplied([]network.RadioBand{network.Band2GHz, network.Band5GHz})},
			{Name: "guest", Bands: network.Supplied([]network.RadioBand{network.Band2GHz})},
			{Name: "disabled-peer", Bands: network.Supplied([]network.RadioBand{network.Band2GHz})},
		})}
		bssRequest := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{
			{Name: "guest"},
			{Name: "disabled-peer"},
			{Name: "legacy", BSSTransition: network.Supplied(network.BSSTransitionDisabled)},
			{Name: "fixture-wifi"},
		})}
		result, err := registry.CompileAP(descriptor, profile.CompilationInput{Baseline: bssBaseline, AP: &bssConfig}, bssRequest, nil)
		if err != nil {
			t.Fatal(err)
		}
		aaaPrefixes := func(identity string) []string {
			var prefixes []string
			for _, binding := range result.Bindings {
				if binding.Kind == "wifi" && binding.Identity == identity {
					prefixes = append(prefixes, binding.Prefixes[1])
				}
			}
			return prefixes
		}
		legacyAAAPrefixes := aaaPrefixes("legacy")
		if len(legacyAAAPrefixes) != 2 {
			t.Fatal("legacy network did not retain both radio bindings")
		}
		for _, prefix := range legacyAAAPrefixes {
			if result.Param.System[prefix+"bss_transition"] != "disabled" {
				t.Fatal("legacy network retained BSS Transition")
			}
		}
		for _, identity := range []string{"fixture-wifi", "disabled-peer", "guest"} {
			for _, prefix := range aaaPrefixes(identity) {
				key := prefix + "bss_transition"
				beforeValue, beforeExists := bssBaseline.System[key]
				afterValue, afterExists := result.Param.System[key]
				if beforeValue != afterValue || beforeExists != afterExists {
					t.Fatal("peer BSS Transition changed")
				}
			}
		}

		managementBody, err := result.Param.Management.Encode()
		if err != nil {
			t.Fatal(err)
		}
		systemBody, err := result.Param.System.Encode()
		if err != nil {
			t.Fatal(err)
		}
		loadedManagement, err := configmap.Parse(managementBody)
		if err != nil {
			t.Fatal(err)
		}
		loadedSystem, err := configmap.Parse(systemBody)
		if err != nil {
			t.Fatal(err)
		}
		unrelated := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{
			{Name: "fixture-wifi"},
			{Name: "legacy", Enabled: network.Supplied(false)},
			{Name: "disabled-peer"},
			{Name: "guest"},
		})}
		repeated, err := registry.CompileAP(descriptor, profile.CompilationInput{
			Baseline: profile.SetParam{Version: result.Param.Version, Management: loadedManagement, System: loadedSystem},
			AP:       result.AP,
			Bindings: result.Bindings,
		}, unrelated, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, identity := range []string{"legacy", "fixture-wifi", "disabled-peer", "guest"} {
			for _, prefix := range aaaPrefixes(identity) {
				key := prefix + "bss_transition"
				want, wantExists := result.Param.System[key]
				got, gotExists := repeated.Param.System[key]
				if got != want || gotExists != wantExists {
					t.Fatal("omitted BSS Transition changed after baseline reload")
				}
			}
		}
	})
	t.Run("clear VLAN and channel", func(t *testing.T) {
		req := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{{Name: "fixture-wifi"}, {Name: "legacy", VLAN: network.Cleared[network.VLANID]()}, {Name: "guest"}}), Radios: network.Supplied([]network.RadioConfig{{Band: network.Band2GHz, Channel: network.Cleared[uint16]()}, {Band: network.Band5GHz}})}
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
		req := network.APConfig{Radios: network.Supplied([]network.RadioConfig{{Band: network.Band2GHz, Channel: network.Supplied(uint16(6))}, {Band: network.Band5GHz}})}
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
	t.Run("radio removal rejects unprojected WLAN", func(t *testing.T) {
		prior := network.APConfig{Radios: network.Supplied([]network.RadioConfig{{Band: network.Band2GHz}})}
		unprojected := profile.CompilationInput{Baseline: baseline, AP: &prior}
		req := network.APConfig{Radios: network.Supplied([]network.RadioConfig{})}
		if _, err := registry.CompileAP(descriptor, unprojected, req, nil); err == nil {
			t.Fatal("radio removal accepted retained unprojected WLAN references")
		}
		if !maps.Equal(baseline.System, before) {
			t.Fatal("rejected radio removal mutated baseline")
		}
	})
	t.Run("primary removal preserves retained virtual subtree", func(t *testing.T) {
		retained := input
		retained.Baseline.System = before.Clone()
		virtual := "radio.2.virtual.9."
		retained.Baseline.System[virtual+"devname"] = "ath2"
		retained.Baseline.System[virtual+"status"] = "enabled"
		retained.Baseline.System[virtual+"operator.unmodeled"] = "retain-virtual"
		req := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{{Name: "fixture-wifi"}, {Name: "guest"}})}
		result, err := registry.CompileAP(descriptor, retained, req, nil)
		if err != nil {
			t.Fatal(err)
		}
		if result.Param.System["radio.2.devname"] != "ath2" {
			t.Fatal("primary reference did not move to retained interface")
		}
		for key, value := range retained.Baseline.System {
			if strings.HasPrefix(key, virtual) && result.Param.System[key] != value {
				t.Fatal("primary promotion erased retained virtual-radio policy")
			}
		}
	})
	t.Run("VLAN move and band addition preserve member policy", func(t *testing.T) {
		moved := input
		moved.Baseline.System = before.Clone()
		moved.Baseline.System["bridge.2.port.2.operator.unmodeled"] = "retain-member"
		req := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{{Name: "fixture-wifi"}, {Name: "legacy", VLAN: network.Cleared[network.VLANID](), Bands: network.Supplied([]network.RadioBand{network.Band2GHz, network.Band5GHz})}, {Name: "guest"}})}
		result, err := registry.CompileAP(descriptor, moved, req, nil)
		if err != nil {
			t.Fatal(err)
		}
		members := 0
		for _, binding := range result.Bindings {
			if binding.Kind != "wifi" || binding.Identity != "legacy" {
				continue
			}
			if result.Param.System[binding.Prefixes[1]+"br.devname"] != "br0" {
				t.Fatal("added band retained the obsolete VLAN")
			}
			for _, prefix := range binding.Prefixes {
				if strings.HasPrefix(prefix, "bridge.") {
					members++
					if result.Param.System[prefix+"operator.unmodeled"] != "retain-member" {
						t.Fatal("combined VLAN move and band addition lost member policy")
					}
				}
			}
		}
		if members != 2 {
			t.Fatal("combined request did not bind both WLAN members")
		}
	})
	t.Run("stable repeated-band radio identities", func(t *testing.T) {
		multiDescriptor := descriptor
		multiDescriptor.Radios = append(append([]profile.RadioCapability(nil), descriptor.Radios...), profile.RadioCapability{
			ID: "wifi-na-b", Interface: "wifi-na-b", Band: network.Band5GHz,
		})
		multiBaseline := profile.SetParam{Management: baseline.Management.Clone(), System: before.Clone()}
		for key, value := range multiBaseline.System.Clone() {
			if strings.HasPrefix(key, "radio.1.") {
				multiBaseline.System["radio.3."+strings.TrimPrefix(key, "radio.1.")] = value
			}
		}
		multiBaseline.System["radio.3.phyname"] = "wifi-na-b"
		delete(multiBaseline.System, "radio.3.devname")
		multiBaseline.System["radio.3.operator.unmodeled"] = "retain-radio"
		multiConfig := network.APConfig{
			Radios: network.Supplied([]network.RadioConfig{
				{ID: "wifi-ng", Band: network.Band2GHz},
				{ID: "wifi-na", Band: network.Band5GHz},
				{ID: "wifi-na-b", Band: network.Band5GHz},
			}),
			Networks: network.Supplied([]network.WiFiNetwork{
				{Name: "fixture-wifi", RadioIDs: network.Supplied([]network.RadioID{"wifi-na"})},
				{Name: "legacy", Bands: network.Supplied([]network.RadioBand{network.Band2GHz})},
				{Name: "guest", Bands: network.Supplied([]network.RadioBand{network.Band2GHz})},
			}),
		}
		secretPath := filepath.Join(t.TempDir(), "psk")
		if err := os.WriteFile(secretPath, []byte("fixture-passphrase"), 0o600); err != nil {
			t.Fatal(err)
		}
		security := network.Supplied(network.WiFiSecurity{
			Mode: network.Supplied(network.WPA2Personal),
			PSK:  network.Supplied(network.SecretFile(secretPath)),
		})
		newNetwork := func(name string) network.WiFiNetwork {
			return network.WiFiNetwork{
				Name: name, Enabled: network.Supplied(true), VLAN: network.Cleared[network.VLANID](),
				BSSTransition: network.Supplied(network.BSSTransitionDisabled), Security: security,
			}
		}
		allFive := newNetwork("all-five")
		allFive.Bands = network.Supplied([]network.RadioBand{network.Band5GHz})
		oneFive := newNetwork("one-five")
		oneFive.RadioIDs = network.Supplied([]network.RadioID{"wifi-na-b"})
		requestNetworks := []network.WiFiNetwork{{Name: "fixture-wifi"}, {Name: "legacy"}, {Name: "guest"}}
		requestNetworks = append(requestNetworks, allFive, oneFive)
		result, err := registry.CompileAP(multiDescriptor, profile.CompilationInput{
			Baseline: multiBaseline,
			AP:       &multiConfig,
		}, network.APConfig{Networks: network.Supplied(requestNetworks)}, fileSecrets{})
		if err != nil {
			t.Fatal(err)
		}
		selected := map[string][]string{}
		interfaces := map[string]bool{}
		for _, binding := range result.Bindings {
			if binding.Kind != "wifi" {
				continue
			}
			if binding.Identity == "all-five" || binding.Identity == "one-five" {
				selected[binding.Identity] = append(selected[binding.Identity], binding.RadioID)
			}
			deviceName := result.Param.System[binding.Prefixes[0]+"devname"]
			if interfaces[deviceName] {
				t.Fatal("generated device interface is not unique")
			}
			interfaces[deviceName] = true
		}
		if !reflect.DeepEqual(selected["all-five"], []string{"wifi-na", "wifi-na-b"}) || !reflect.DeepEqual(selected["one-five"], []string{"wifi-na-b"}) {
			t.Fatalf("selected radio bindings = %v", selected)
		}
		if result.Param.System["radio.3.operator.unmodeled"] != "retain-radio" {
			t.Fatal("repeated-band composition lost unknown radio policy")
		}
		if result.AP == nil || result.AP.Radios.Value[0].ID == "" || result.AP.Radios.Value[1].ID == "" || result.AP.Radios.Value[2].ID == "" {
			t.Fatal("compiled projection did not persist stable radio IDs")
		}
		reorderedRadios := network.APConfig{Radios: network.Supplied([]network.RadioConfig{
			{ID: "wifi-na-b", Band: network.Band5GHz},
			{ID: "wifi-ng", Band: network.Band2GHz},
			{ID: "wifi-na", Band: network.Band5GHz},
		})}
		reordered, err := registry.CompileAP(multiDescriptor, profile.CompilationInput{
			Baseline: result.Param,
			AP:       result.AP,
			Bindings: result.Bindings,
		}, reorderedRadios, nil)
		if err != nil {
			t.Fatal(err)
		}
		if reordered.Param.Version != result.Param.Version || reordered.Param.System["radio.3.operator.unmodeled"] != "retain-radio" || !reflect.DeepEqual(reordered.Bindings, result.Bindings) {
			t.Fatal("radio request ordering changed stable ownership or policy")
		}
		tamperedBindings := profile.CloneBindings(result.Bindings)
		for index := range tamperedBindings {
			if tamperedBindings[index].Kind == "wifi" {
				tamperedBindings[index].RadioID = "wrong-stable-id"
				break
			}
		}
		if _, err := registry.CompileAP(multiDescriptor, profile.CompilationInput{
			Baseline: result.Param,
			AP:       result.AP,
			Bindings: tamperedBindings,
		}, network.APConfig{}, nil); err == nil {
			t.Fatal("mismatched stable binding was accepted as a legacy migration")
		}

		missing := multiConfig.Clone()
		missing.Radios.Value[2].ID = "missing-radio"
		if _, err := registry.CompileAP(multiDescriptor, profile.CompilationInput{Baseline: multiBaseline, AP: &missing}, network.APConfig{}, nil); err == nil {
			t.Fatal("missing radio ID was accepted")
		}
		ambiguousPrior := multiConfig.Clone()
		ambiguousPrior.Radios.Value = ambiguousPrior.Radios.Value[:2]
		if _, err := registry.CompileAP(multiDescriptor, profile.CompilationInput{Baseline: multiBaseline, AP: &ambiguousPrior}, network.APConfig{Radios: network.Supplied([]network.RadioConfig{
			{ID: "wifi-ng", Band: network.Band2GHz},
			{Band: network.Band5GHz},
		})}, nil); err == nil {
			t.Fatal("prior projection resolved an inventory-ambiguous radio request")
		}
		syntheticDescriptor := multiDescriptor
		syntheticDescriptor.Radios = append(append([]profile.RadioCapability(nil), descriptor.Radios...), profile.RadioCapability{
			ID: "radio-9", SyntheticID: true, Interface: "wifi-synthetic", Band: network.Band5GHz,
		})
		unrelatedConfig := network.APConfig{
			Radios: network.Supplied([]network.RadioConfig{{Band: network.Band2GHz}}),
			Networks: network.Supplied([]network.WiFiNetwork{
				{Name: "legacy", Bands: network.Supplied([]network.RadioBand{network.Band2GHz})},
				{Name: "guest", Bands: network.Supplied([]network.RadioBand{network.Band2GHz})},
			}),
		}
		if _, err := registry.CompileAP(syntheticDescriptor, profile.CompilationInput{Baseline: multiBaseline, AP: &unrelatedConfig}, network.APConfig{}, nil); err != nil {
			t.Fatal("unrelated synthetic observation blocked a stable target", err)
		}
		syntheticConfig := network.APConfig{Radios: network.Supplied([]network.RadioConfig{{ID: "radio-9", Band: network.Band5GHz}})}
		if _, err := registry.CompileAP(syntheticDescriptor, profile.CompilationInput{Baseline: multiBaseline, AP: &syntheticConfig}, network.APConfig{}, nil); err == nil {
			t.Fatal("synthetic radio ID was accepted as a mutation target")
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
	if err := json.Unmarshal([]byte(`{"radio_table":[{"name":"wifi0","radio":"ng"},{"name":"wifi1","radio":"na"}],"vap_table":[{"radio":"ng","radio_name":"wifi0","channel":6,"bw":"20","tx_power":10,"num_sta":0,"sta_table":[{"mac":"02:00:00:00:00:03"}]},{"radio":"na","radio_name":"wifi1","channel":44,"bw":40,"tx_power":12}]} `), &physicalReport); err != nil {
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
	if len(physicalSnapshot.Clients) != 1 || physicalSnapshot.Clients[0].RadioID != "wifi0" {
		t.Fatal("client snapshot did not use stable physical radio identity")
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

func TestAPCompilerResolvesBoundBaselinePolicy(t *testing.T) {
	minimum, maximum := 1, 30
	descriptor := profile.DeviceDescriptor{
		Family: network.FamilyAP, Model: "U7PG2", Firmware: "6.8.2.15592",
		Protocol: profile.ProtocolCapabilities{PacketVersion: 1, PayloadVersion: 1, SystemConfig: true, ManagementConfig: true},
		Radios:   []profile.RadioCapability{{ID: "wifi0", Interface: "wifi0", Band: network.Band2GHz, MinPowerDBm: &minimum, MaxPowerDBm: &maximum}},
	}
	projection := network.APConfig{
		Networks: network.Supplied([]network.WiFiNetwork{{Name: "fixture", Bands: network.Supplied([]network.RadioBand{network.Band2GHz})}}),
		Radios:   network.Supplied([]network.RadioConfig{{ID: "wifi0", Band: network.Band2GHz}}),
	}
	baseline := profile.SetParam{
		Management: configmap.Values{"cfgversion": "fixture"},
		System: configmap.Values{
			"radio.1.phyname": "wifi0", "radio.1.devname": "wifi0ap0", "radio.1.channel": "6", "radio.1.ieee_mode": "11nght20", "radio.1.txpower_mode": "custom", "radio.1.txpower": "18",
			"wireless.1.ssid": "fixture", "wireless.1.parent": "wifi0", "wireless.1.devname": "wifi0ap0", "wireless.1.status": "enabled", "wireless.1.security": "none",
			"aaa.1.ssid": "fixture", "aaa.1.devname": "wifi0ap0", "aaa.1.status": "enabled", "aaa.1.br.devname": "br0", "aaa.1.wpa": "0",
			"bridge.1.devname": "br0", "bridge.1.port.1.devname": "wifi0ap0",
		},
	}
	input := profile.CompilationInput{AP: &projection, Baseline: baseline}
	beforeProjection := projection.Clone()

	t.Run("security mode requires effective key", func(t *testing.T) {
		request := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{{
			Name: "fixture", Security: network.Supplied(network.WiFiSecurity{Mode: network.Supplied(network.WPA2Personal)}),
		}})}
		if _, err := ap.New().Compile(descriptor, input, request, nil); err == nil {
			t.Fatal("open baseline changed to WPA2 without a key")
		}
		secured := input
		secured.Baseline.System = baseline.System.Clone()
		secured.Baseline.System["aaa.1.wpa.psk"] = "fixture-passphrase"
		result, err := ap.New().Compile(descriptor, secured, request, nil)
		if err != nil || result.Param.System["aaa.1.wpa.psk"] != "fixture-passphrase" {
			t.Fatal("valid bound baseline key was not retained", err)
		}
	})
	t.Run("empty security preserves baseline", func(t *testing.T) {
		preserved := input
		preserved.Baseline.System = baseline.System.Clone()
		preserved.Baseline.System["aaa.1.bss_transition"] = "disabled"
		preserved.Baseline.System["aaa.1.operator.unknown"] = "retain"
		request := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{{
			Name: "fixture", Enabled: network.Supplied(false), Security: network.Supplied(network.WiFiSecurity{}),
		}})}
		result, err := ap.New().Compile(descriptor, preserved, request, nil)
		if err != nil {
			t.Fatal("empty security changed the effective security policy", err)
		}
		expected := preserved.Baseline.System.Clone()
		expected["wireless.1.status"], expected["aaa.1.status"] = "disabled", "disabled"
		if !maps.Equal(result.Param.System, expected) {
			t.Fatal("empty security changed retained baseline records")
		}
	})
	t.Run("power value validates resolved mode", func(t *testing.T) {
		automatic := input
		automatic.Baseline.System = baseline.System.Clone()
		automatic.Baseline.System["radio.1.txpower_mode"] = "auto"
		automatic.Baseline.System["radio.1.txpower"] = "auto"
		request := network.APConfig{Radios: network.Supplied([]network.RadioConfig{{
			ID: "wifi0", Band: network.Band2GHz, Power: network.Supplied(network.PowerConfig{DBm: network.Supplied(20)}),
		}})}
		if _, err := ap.New().Compile(descriptor, automatic, request, nil); err == nil {
			t.Fatal("explicit power value was accepted with bound automatic mode")
		}
	})

	tests := []struct {
		name    string
		request network.RadioConfig
		assert  func(configmap.Values) bool
	}{
		{name: "power value", request: network.RadioConfig{ID: "wifi0", Band: network.Band2GHz, Power: network.Supplied(network.PowerConfig{DBm: network.Supplied(20)})}, assert: func(values configmap.Values) bool {
			return values["radio.1.txpower_mode"] == "custom" && values["radio.1.txpower"] == "20"
		}},
		{name: "power mode", request: network.RadioConfig{ID: "wifi0", Band: network.Band2GHz, Power: network.Supplied(network.PowerConfig{Mode: network.Supplied(network.PowerExplicit)})}, assert: func(values configmap.Values) bool {
			return values["radio.1.txpower_mode"] == "custom" && values["radio.1.txpower"] == "18"
		}},
		{name: "channel", request: network.RadioConfig{ID: "wifi0", Band: network.Band2GHz, Channel: network.Supplied(uint16(6))}, assert: func(values configmap.Values) bool {
			return values["radio.1.channel"] == "6" && values["radio.1.ieee_mode"] == "11nght20"
		}},
		{name: "width", request: network.RadioConfig{ID: "wifi0", Band: network.Band2GHz, WidthMHz: network.Supplied(network.Width40)}, assert: func(values configmap.Values) bool {
			return values["radio.1.channel"] == "6" && values["radio.1.ieee_mode"] == "11nght40"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := ap.New().Compile(descriptor, input, network.APConfig{Radios: network.Supplied([]network.RadioConfig{test.request})}, nil)
			if err != nil {
				t.Fatal("partial radio request rejected", err)
			}
			if !test.assert(result.Param.System) {
				t.Fatal("partial radio request lost bound baseline policy")
			}
		})
	}
	if !reflect.DeepEqual(projection, beforeProjection) {
		t.Fatal("bound policy resolution changed the identity-only projection")
	}
}
