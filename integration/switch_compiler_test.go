package integration_test

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GehirnInc/crypt/sha512_crypt"

	"goodkind.io/unifi-go/internal/configmap"
	"goodkind.io/unifi-go/internal/informmodel"
	"goodkind.io/unifi-go/internal/profile"
	"goodkind.io/unifi-go/internal/profile/switches"
	"goodkind.io/unifi-go/network"
)

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
	config := network.SwitchConfig{Ports: []network.SwitchPortConfig{
		{Index: 5, Enabled: true, NativeVLAN: 1, PoE: network.PoEAuto},
		{Index: 3, Enabled: true, NativeVLAN: 1, TaggedVLANs: []network.VLANID{20}},
		{Index: 2, Enabled: true, NativeVLAN: 20},
		{Index: 4, Enabled: false, NativeVLAN: 1, PoE: network.PoEOff},
	}}
	compiled, err := switches.New().Compile(descriptor, config, nil)
	if err != nil {
		t.Fatal(err)
	}
	physicalProtocol := descriptor
	physicalProtocol.Protocol.PacketVersion = 0
	versionZero, err := switches.New().Compile(physicalProtocol, config, nil)
	if err != nil || versionZero.Version != compiled.Version {
		t.Fatal("verified physical packet version 0 changed or rejected switch compilation")
	}
	expected := configmap.Values{
		"switch.vlan.1.id": "1", "switch.vlan.1.mode": "untagged",
		"switch.vlan.1.status": "enabled", "switch.vlan.2.id": "20",
		"switch.vlan.2.mode": "tagged", "switch.vlan.2.status": "enabled",
		"switch.port.2.opmode": "switch", "switch.port.2.status": "enabled",
		"switch.port.2.pvid": "20", "switch.vlan.1.port.2.mode": "exclude",
		"switch.vlan.2.port.2.mode": "untagged",
		"switch.port.3.opmode":      "switch", "switch.port.3.status": "enabled",
		"switch.port.3.pvid": "1", "switch.vlan.1.port.3.mode": "untagged",
		"switch.vlan.2.port.3.mode": "tagged",
		"switch.port.4.opmode":      "switch", "switch.port.4.status": "disabled",
		"switch.port.4.pvid": "1", "switch.port.4.poe": "shutdown",
		"switch.vlan.1.port.4.mode": "untagged", "switch.vlan.2.port.4.mode": "exclude",
		"switch.port.5.opmode": "switch", "switch.port.5.status": "enabled",
		"switch.port.5.pvid": "1", "switch.port.5.poe": "auto",
		"switch.vlan.1.port.5.mode": "untagged", "switch.vlan.2.port.5.mode": "exclude",
	}
	if compiled.Version == "" || !maps.Equal(compiled.System, expected) {
		t.Fatalf("compiled switch map differs from reference-backed keys: %#v", compiled.System)
	}
	if _, exists := compiled.System["switch.port.2.poe"]; exists {
		t.Fatal("empty PoE request emitted a key")
	}
	for key := range compiled.System {
		if strings.HasPrefix(key, "sshd.") || strings.HasPrefix(key, "users.") {
			t.Fatal("configuration without SSH emitted credential keys")
		}
	}
	repeated, err := switches.New().Compile(descriptor, config, nil)
	if err != nil || repeated.Version != compiled.Version || !maps.Equal(repeated.System, compiled.System) {
		t.Fatal("switch compilation is not deterministic")
	}
	unfamiliar := descriptor
	unfamiliar.Model = "UNFAMILIAR-SWITCH"
	unfamiliar.Firmware = "99.88.77"
	unfamiliarCompiled, err := switches.New().Compile(unfamiliar, config, nil)
	if err != nil || unfamiliarCompiled.Version != compiled.Version || !maps.Equal(unfamiliarCompiled.System, compiled.System) {
		t.Fatal("model or firmware changed capability-equivalent compilation")
	}
	passwordPath := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(passwordPath, []byte("fixture-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sshConfig := config
	sshConfig.SSH = &network.SSHConfig{Username: "fixture-user", Password: network.SecretFile(passwordPath)}
	sshCompiled, err := switches.New().Compile(descriptor, sshConfig, fileSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	if sshCompiled.System["sshd.1.ifname"] != "eth0" || sshCompiled.System["users.1.name"] != "fixture-user" {
		t.Fatal("requested SSH configuration compiled incorrectly")
	}
	if err := sha512_crypt.New().Verify(sshCompiled.System["users.1.password"], []byte("fixture-password")); err != nil {
		t.Fatal("SSH password hash does not verify")
	}
	repeatedSSH, err := switches.New().Compile(descriptor, sshConfig, fileSecrets{})
	if err != nil || repeatedSSH.System["users.1.password"] != sshCompiled.System["users.1.password"] {
		t.Fatal("SSH password hash is not deterministic")
	}
	vlanSupported := true
	managementDescriptor := profile.DeviceDescriptor{
		Family: network.FamilySwitch, Protocol: descriptor.Protocol,
		Ports: []profile.PortCapability{
			{Index: 7, Interface: "eth6", VLAN: &vlanSupported},
			{Index: 1, Interface: ""},
		},
	}
	managementConfig := network.SwitchConfig{
		Ports: []network.SwitchPortConfig{{Index: 7, Enabled: true, NativeVLAN: 1}},
		SSH:   sshConfig.SSH,
	}
	managementCompiled, err := switches.New().Compile(managementDescriptor, managementConfig, fileSecrets{})
	if err != nil || managementCompiled.System["sshd.1.ifname"] != "eth6" {
		t.Fatal("SSH did not select the lowest reported nonempty interface")
	}
	managementDescriptor.Ports[0], managementDescriptor.Ports[1] = managementDescriptor.Ports[1], managementDescriptor.Ports[0]
	reorderedManagement, err := switches.New().Compile(managementDescriptor, managementConfig, fileSecrets{})
	if err != nil || reorderedManagement.System["sshd.1.ifname"] != "eth6" || reorderedManagement.Version != managementCompiled.Version {
		t.Fatal("SSH interface selection depends on report order")
	}
	managementDescriptor.Ports[1].Interface = ""
	if _, err := switches.New().Compile(managementDescriptor, managementConfig, fileSecrets{}); err == nil {
		t.Fatal("SSH accepted an inventory without any reported interface")
	}

	noncontiguous := profile.DeviceDescriptor{
		Family: network.FamilySwitch, Model: "SYNTHETIC", Protocol: descriptor.Protocol,
		Ports: []profile.PortCapability{
			{Index: 7, Interface: "eth6", VLAN: &vlanSupported},
			{Index: 2, Interface: "eth1", VLAN: &vlanSupported},
		},
	}
	noncontiguousConfig := network.SwitchConfig{Ports: []network.SwitchPortConfig{
		{Index: 7, Enabled: true, NativeVLAN: 300, TaggedVLANs: []network.VLANID{20}},
		{Index: 2, Enabled: true, NativeVLAN: 1},
	}}
	noncontiguousCompiled, err := switches.New().Compile(noncontiguous, noncontiguousConfig, nil)
	if err != nil {
		t.Fatal(err)
	}
	if noncontiguousCompiled.System["switch.vlan.2.id"] != "20" || noncontiguousCompiled.System["switch.vlan.3.id"] != "300" || noncontiguousCompiled.System["switch.port.7.pvid"] != "300" {
		t.Fatal("noncontiguous ports or sorted VLAN numbering compiled incorrectly")
	}
	secondReport := loadReport("operation-02-report.json")
	secondDescriptor, err := profile.DescribeWithFamily(secondReport, network.FamilySwitch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := switches.New().Compile(secondDescriptor, network.SwitchConfig{Ports: []network.SwitchPortConfig{{Index: 8, Enabled: true, NativeVLAN: 1}}}, nil); err != nil {
		t.Fatal("different non-PoE inventory was rejected")
	}

	missingPort := config
	missingPort.Ports = []network.SwitchPortConfig{{Index: 99, Enabled: true, NativeVLAN: 1}}
	if _, err := switches.New().Compile(descriptor, missingPort, nil); err == nil {
		t.Fatal("missing reported port was accepted")
	}
	duplicatePort := config
	duplicatePort.Ports = []network.SwitchPortConfig{{Index: 2, Enabled: true, NativeVLAN: 1}, {Index: 2, Enabled: true, NativeVLAN: 20}}
	if _, err := switches.New().Compile(descriptor, duplicatePort, nil); err == nil {
		t.Fatal("duplicate requested port was accepted")
	}
	overlap := config
	overlap.Ports = []network.SwitchPortConfig{{Index: 2, Enabled: true, NativeVLAN: 20, TaggedVLANs: []network.VLANID{20}}}
	if _, err := switches.New().Compile(descriptor, overlap, nil); err == nil {
		t.Fatal("native and tagged VLAN overlap was accepted")
	}
	withoutPoE := descriptor
	withoutPoE.Ports = append([]profile.PortCapability(nil), descriptor.Ports...)
	withoutPoE.Ports[1].PoEModes = nil
	if _, err := switches.New().Compile(withoutPoE, network.SwitchConfig{Ports: []network.SwitchPortConfig{{Index: 2, Enabled: true, NativeVLAN: 1, PoE: network.PoEAuto}}}, nil); err == nil {
		t.Fatal("unreported PoE mode was accepted")
	}
	vlanUnsupported := false
	withoutVLAN := descriptor
	withoutVLAN.Ports = append([]profile.PortCapability(nil), descriptor.Ports...)
	withoutVLAN.Ports[1].VLAN = &vlanUnsupported
	if _, err := switches.New().Compile(withoutVLAN, network.SwitchConfig{Ports: []network.SwitchPortConfig{{Index: 2, Enabled: true, NativeVLAN: 1}}}, nil); err == nil {
		t.Fatal("explicitly unsupported VLAN configuration was accepted")
	}
	withoutVLAN.Ports[1].VLAN = nil
	if _, err := switches.New().Compile(withoutVLAN, network.SwitchConfig{Ports: []network.SwitchPortConfig{{Index: 2, Enabled: true, NativeVLAN: 1}}}, nil); err == nil {
		t.Fatal("unknown VLAN capability was accepted")
	}
	unsupportedProtocol := descriptor
	unsupportedProtocol.Protocol.PacketVersion = 2
	if switches.New().Supports(unsupportedProtocol) {
		t.Fatal("unverified packet protocol was accepted")
	}
	unsupportedProtocol.Protocol.PacketVersion, unsupportedProtocol.Protocol.PayloadVersion = 1, 2
	if switches.New().Supports(unsupportedProtocol) {
		t.Fatal("unverified payload protocol was accepted")
	}
	wrongFamily := descriptor
	wrongFamily.Family = network.FamilyAP
	registry := profile.NewRegistry(nil, switches.New())
	if _, err := registry.CompileSwitch(wrongFamily, config, nil); err == nil {
		t.Fatal("switch registry accepted an access point descriptor")
	}

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
