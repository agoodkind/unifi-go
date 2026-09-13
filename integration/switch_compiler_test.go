package integration_test

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"goodkind.io/unifi-go/internal/informmodel"
	"goodkind.io/unifi-go/internal/profile"
	"goodkind.io/unifi-go/internal/profile/switches"
	"goodkind.io/unifi-go/network"
)

func suppliedSwitchPort(index uint16, enabled bool, nativeVLAN network.VLANID, taggedVLANs []network.VLANID, poe network.PoEMode) network.SwitchPortConfig {
	return network.SwitchPortConfig{
		Index: index, Enabled: network.Supplied(enabled), NativeVLAN: network.Supplied(nativeVLAN),
		TaggedVLANs: network.Supplied(taggedVLANs), PoE: network.Supplied(poe),
	}
}

func suppliedSwitchConfig(ports ...network.SwitchPortConfig) network.SwitchConfig {
	return network.SwitchConfig{Ports: network.Supplied(ports)}
}

func TestSwitchCompilerFromNetworkServerFixture(t *testing.T) {
	loadReport := func(name string) informmodel.Report {
		t.Helper()
		body, err := os.ReadFile(filepath.Join("..", "testdata", "profiles", "switch", name))
		if err != nil {
			t.Fatal(err)
		}
		var report informmodel.Report
		if err := json.Unmarshal(body, &report); err != nil {
			t.Fatal(err)
		}
		report.SystemConfig, report.ManagementConfig = true, true
		report.PacketVersion, report.PayloadVersion = 1, 1
		// Added test capability evidence is not part of the captured reference.
		vlanCaps := uint64(1)
		report.SwitchCaps = &informmodel.SwitchCapabilities{VLANCaps: &vlanCaps}
		return report
	}
	report := loadReport("operation-08-report.json")
	descriptor, err := profile.DescribeWithFamily(report, network.FamilySwitch)
	if err != nil {
		t.Fatal(err)
	}
	config := suppliedSwitchConfig(
		suppliedSwitchPort(5, true, 1, []network.VLANID{}, network.PoEAuto),
		suppliedSwitchPort(3, true, 1, []network.VLANID{20}, ""),
		suppliedSwitchPort(2, true, 20, []network.VLANID{}, ""),
		suppliedSwitchPort(4, false, 1, []network.VLANID{}, network.PoEOff),
	)

	baseline := compilerFixture(t, "switch", "operation-08-reply.json")
	// Explicit synthetic status and native policy supplement the captured port records.
	for _, port := range config.Ports.Value {
		prefix := fmt.Sprintf("switch.port.%d.", port.Index)
		baseline.System[prefix+"opmode"] = "switch"
		baseline.System[prefix+"status"] = "enabled"
		baseline.System[prefix+"pvid"] = strconv.Itoa(int(port.NativeVLAN.Value))
		for _, vlanPrefix := range profile.RecordPrefixes(baseline.System, "switch.vlan.") {
			id, err := strconv.Atoi(baseline.System[vlanPrefix+"id"])
			if err != nil {
				t.Fatal(err)
			}
			mode := "exclude"
			if network.VLANID(id) == port.NativeVLAN.Value {
				mode = "untagged"
			} else if slices.Contains(port.TaggedVLANs.Value, network.VLANID(id)) {
				mode = "tagged"
			}
			baseline.System[fmt.Sprintf("%sport.%d.mode", vlanPrefix, port.Index)] = mode
		}
	}
	baseline.System["operator.unmodeled"], baseline.System["locale.timezone"] = "retain", "operator-zone"
	baseline.System["switch.port.2.operator.unmodeled"] = "retain-port"
	baseline.Management["operator.unmodeled"] = "retain-management"
	input := profile.CompilationInput{Baseline: baseline, Switch: &config}
	registry := profile.NewRegistry(nil, switches.New())
	request := network.SwitchConfig{Ports: network.Supplied([]network.SwitchPortConfig{{Index: 2, Enabled: network.Supplied(false)}, {Index: 3}, {Index: 4}, {Index: 5}})}
	before := baseline.System.Clone()
	compiled, err := registry.CompileSwitch(descriptor, input, request, nil)
	if err != nil {
		t.Fatal("baseline composition failed", err)
	}
	expected := before.Clone()
	expected["switch.port.2.status"] = "disabled"
	assertComposition(t, compiled.Param, baseline.Management, expected)
	if !maps.Equal(before, baseline.System) || !config.Ports.Value[2].Enabled.Value {
		t.Fatal("input mutated")
	}
	if compiled.Switch == nil || compiled.AP != nil {
		t.Fatal("wrong result family")
	}
	repeated, err := registry.CompileSwitch(descriptor, profile.CompilationInput{Baseline: compiled.Param, Switch: compiled.Switch, Bindings: compiled.Bindings}, request, nil)
	if err != nil || repeated.Param.Version != compiled.Param.Version || !reflect.DeepEqual(repeated.Bindings, compiled.Bindings) {
		t.Fatal("repeated compilation changed identity")
	}
	unfamiliar := descriptor
	unfamiliar.Model = "UNRECOGNIZED"
	unfamiliar.Ports = append([]profile.PortCapability(nil), descriptor.Ports...)
	for index := range unfamiliar.Ports {
		unfamiliar.Ports[index].VLAN = nil
		unfamiliar.Ports[index].PoEModes = nil
	}
	if _, err := registry.CompileSwitch(unfamiliar, input, request, nil); err != nil {
		t.Fatal("untouched capability blocked enabled setting")
	}
	t.Run("omitted collection", func(t *testing.T) {
		result, err := registry.CompileSwitch(descriptor, input, network.SwitchConfig{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		assertComposition(t, result.Param, baseline.Management, before)
	})
	t.Run("empty collection removes only owned ports", func(t *testing.T) {
		result, err := registry.CompileSwitch(descriptor, input, network.SwitchConfig{Ports: network.Supplied([]network.SwitchPortConfig{})}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if result.Param.System["switch.port.2.operator.unmodeled"] != "" || result.Param.System["operator.unmodeled"] != "retain" || result.Param.System["switch.port.1.pvid"] != before["switch.port.1.pvid"] {
			t.Fatal("removed unrelated policy")
		}
	})
	t.Run("explicit empty tagged collection", func(t *testing.T) {
		req := network.SwitchConfig{Ports: network.Supplied([]network.SwitchPortConfig{{Index: 2}, {Index: 3, TaggedVLANs: network.Supplied([]network.VLANID{})}, {Index: 4}, {Index: 5}})}
		result, err := registry.CompileSwitch(descriptor, input, req, nil)
		if err != nil {
			t.Fatal(err)
		}
		if result.Param.System["switch.vlan.2.port.3.mode"] != "exclude" {
			t.Fatal("explicit empty tagged VLANs were omitted")
		}
		if _, err := registry.CompileSwitch(unfamiliar, input, req, nil); err == nil {
			t.Fatal("missing VLAN capability accepted")
		}
	})
	t.Run("new port requires policy", func(t *testing.T) {
		if _, err := registry.CompileSwitch(descriptor, input, network.SwitchConfig{Ports: network.Supplied([]network.SwitchPortConfig{{Index: 7}})}, nil); err == nil {
			t.Fatal("new port used hidden policy")
		}
	})

	t.Run("add explicit physical port", func(t *testing.T) {
		req := network.SwitchConfig{Ports: network.Supplied([]network.SwitchPortConfig{{Index: 2}, {Index: 3}, {Index: 4}, {Index: 5}, suppliedSwitchPort(7, false, 1, []network.VLANID{}, network.PoEAuto)})}
		result, err := registry.CompileSwitch(descriptor, input, req, nil)
		if err != nil {
			t.Fatal(err)
		}
		if result.Param.System["switch.port.7.status"] != "disabled" || result.Param.System["switch.port.7.pvid"] != "1" {
			t.Fatal("added port policy missing")
		}
		for key, value := range before {
			if strings.HasPrefix(key, "switch.port.7.") || strings.Contains(key, ".port.7.") {
				continue
			}
			if result.Param.System[key] != value {
				t.Fatal("port addition changed unrelated policy")
			}
		}
	})
	t.Run("PoE alone preserves VLAN policy", func(t *testing.T) {
		req := network.SwitchConfig{Ports: network.Supplied([]network.SwitchPortConfig{{Index: 2}, {Index: 3}, {Index: 4, PoE: network.Supplied(network.PoEOff)}, {Index: 5}})}
		result, err := registry.CompileSwitch(descriptor, input, req, nil)
		if err != nil {
			t.Fatal(err)
		}
		want := before.Clone()
		want["switch.port.4.poe"] = "shutdown"
		assertComposition(t, result.Param, baseline.Management, want)
		if _, err := registry.CompileSwitch(unfamiliar, input, req, nil); err == nil {
			t.Fatal("missing PoE evidence accepted")
		}
	})
	t.Run("untouched absent port policy", func(t *testing.T) {
		sparse := input
		sparse.Baseline.System = before.Clone()
		delete(sparse.Baseline.System, "switch.port.2.status")
		delete(sparse.Baseline.System, "switch.port.2.pvid")
		sparse.Baseline.System["switch.port.2.opmode"] = "operator-mode"
		result, err := registry.CompileSwitch(descriptor, sparse, request, nil)
		if err != nil {
			t.Fatal(err)
		}
		want := sparse.Baseline.System.Clone()
		want["switch.port.2.status"] = "disabled"
		assertComposition(t, result.Param, baseline.Management, want)
	})
	snapshot, err := switches.New().Decode(report)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Ports) != 8 || snapshot.Ports[0].Up == nil || !*snapshot.Ports[0].Up || snapshot.Ports[0].RxBytes == nil || *snapshot.Ports[0].RxBytes != 0 || snapshot.Ports[0].PoEMode != "" {
		t.Fatal("real switch measurements decoded incorrectly")
	}
	var optionalReport informmodel.Report
	if err := json.Unmarshal([]byte(`{"port_table":[{"port_idx":7,"ifname":"eth6","up":false,"speed":0,"full_duplex":false,"rx_bytes":0,"tx_bytes":0,"port_poe":false},{"port_idx":2,"name":"absent"}]}`), &optionalReport); err != nil {
		t.Fatal(err)
	}
	optionalSnapshot, err := switches.New().Decode(optionalReport)
	if err != nil {
		t.Fatal(err)
	}
	absent := optionalSnapshot.Ports[0]
	zero := optionalSnapshot.Ports[1]
	if absent.Index != 2 || zero.Index != 7 {
		t.Fatal("decoded switch ports were not sorted by physical index")
	}
	if absent.Up != nil || absent.SpeedMbps != nil || absent.RxBytes != nil || absent.NativeVLAN != nil || absent.PoEMode != "" {
		t.Fatal("absent switch observations were synthesized")
	}
	if zero.Up == nil || *zero.Up || zero.SpeedMbps == nil || *zero.SpeedMbps != 0 || zero.FullDuplex == nil || *zero.FullDuplex || zero.RxBytes == nil || *zero.RxBytes != 0 || zero.TxBytes == nil || *zero.TxBytes != 0 || zero.PoEMode != "" {
		t.Fatal("reported zero switch observations were lost")
	}
	// These fields reproduce the test-only emulator observation contract.
	var reflected informmodel.Report
	if err := json.Unmarshal([]byte(`{"port_table":[{"port_idx":2,"native_vlan":20,"tagged_vlans":[],"poe_mode":"off"},{"port_idx":7,"native_vlan":1,"tagged_vlans":[20,30],"poe_mode":"auto"}]}`), &reflected); err != nil {
		t.Fatal(err)
	}
	reflectedSnapshot, err := switches.New().Decode(reflected)
	if err != nil || reflectedSnapshot.Ports[0].NativeVLAN == nil || *reflectedSnapshot.Ports[0].NativeVLAN != 20 || reflectedSnapshot.Ports[0].TaggedVLANs == nil || reflectedSnapshot.Ports[0].PoEMode != network.PoEOff || len(reflectedSnapshot.Ports[1].TaggedVLANs) != 2 || reflectedSnapshot.Ports[1].PoEMode != network.PoEAuto {
		t.Fatal("reported switch configuration was not decoded")
	}
	reflected.PortTable[1].TaggedVLANs = []uint16{20, 20}
	if _, err := switches.New().Decode(reflected); err == nil {
		t.Fatal("duplicate reported tagged VLAN was accepted")
	}
	reflected.PortTable[1].TaggedVLANs = []uint16{1}
	if _, err := switches.New().Decode(reflected); err == nil {
		t.Fatal("native and tagged observation overlap was accepted")
	}
	reflected.PortTable[1].TaggedVLANs = []uint16{4095}
	if _, err := switches.New().Decode(reflected); err == nil {
		t.Fatal("out-of-range observed VLAN was accepted")
	}
	reflected.PortTable[1].TaggedVLANs = nil
	reflected.PortTable[1].PoEMode = "passive"
	if _, err := switches.New().Decode(reflected); err == nil {
		t.Fatal("unverified observed PoE mode was accepted")
	}
}
