package integration_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GehirnInc/crypt/sha512_crypt"

	"goodkind.io/unifi-go/internal/informmodel"
	"goodkind.io/unifi-go/internal/profile"
	"goodkind.io/unifi-go/internal/profile/ap"
	"goodkind.io/unifi-go/network"
)

type fileSecrets struct{}

func (fileSecrets) ReadSecret(path network.SecretFile) ([]byte, error) {
	return os.ReadFile(string(path))
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
	unsupportedProtocol := descriptor
	unsupportedProtocol.Protocol.PayloadVersion = 2
	if ap.New().Supports(unsupportedProtocol) {
		t.Fatal("unverified payload protocol was accepted")
	}
	secretPath := filepath.Join(t.TempDir(), "psk")
	if err := os.WriteFile(secretPath, []byte("fixture-passphrase"), 0o600); err != nil {
		t.Fatal(err)
	}
	vlan := network.VLANID(20)
	secondVLAN := network.VLANID(30)
	config := network.APConfig{
		CountryCode: 840,
		Networks: []network.WiFiNetwork{{
			Name: "fixture-wifi", Enabled: true, VLAN: &vlan,
			Bands:    []network.RadioBand{network.Band2GHz, network.Band5GHz},
			Security: network.WiFiSecurity{Mode: network.WPA2Personal, PSK: network.SecretFile(secretPath)},
		}, {
			Name: "fixture-iot", Enabled: true, VLAN: &secondVLAN,
			Bands:    []network.RadioBand{network.Band2GHz},
			Security: network.WiFiSecurity{Mode: network.WPA2Personal, PSK: network.SecretFile(secretPath)},
		}},
		Radios: []network.RadioConfig{
			{Band: network.Band2GHz, Enabled: true, WidthMHz: network.Width20, Power: network.PowerConfig{Mode: network.PowerAuto}},
			{Band: network.Band5GHz, Enabled: true, WidthMHz: network.Width40, Power: network.PowerConfig{Mode: network.PowerAuto}},
		},
		SSH: &network.SSHConfig{Username: "fixture-user", Password: network.SecretFile(secretPath)},
	}
	compiled, err := ap.New().Compile(descriptor, config, fileSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	physicalProtocol := descriptor
	physicalProtocol.Protocol.PacketVersion = 0
	versionZero, err := ap.New().Compile(physicalProtocol, config, fileSecrets{})
	if err != nil || versionZero.Version != compiled.Version {
		t.Fatal("verified physical packet version 0 changed or rejected AP compilation")
	}
	unsupportedProtocol.Protocol.PacketVersion, unsupportedProtocol.Protocol.PayloadVersion = 2, 1
	if _, err := ap.New().Compile(unsupportedProtocol, config, fileSecrets{}); err == nil {
		t.Fatal("unverified packet version 2 allowed AP compilation")
	}
	if compiled.Version == "" || compiled.System["radio.1.phyname"] != "wifi-na" || compiled.System["radio.2.phyname"] != "wifi-ng" {
		t.Fatal("compiled radio identity or version is incorrect")
	}
	if compiled.System["radio.1.devname"] != "ath0" || compiled.System["wireless.1.devname"] != "ath0" {
		t.Fatal("emulator-shaped interfaces did not retain ath VAP names")
	}
	if compiled.System["aaa.1.wpa.psk"] != "fixture-passphrase" || compiled.System["vlan.1.id"] != "20" || compiled.System["bridge.2.devname"] != "br0.20" {
		t.Fatal("compiled WPA2 VLAN behavior is incorrect")
	}
	if compiled.System["wireless.2.devname"] == compiled.System["wireless.3.devname"] || compiled.System["aaa.2.br.devname"] != "br0.20" || compiled.System["aaa.3.br.devname"] != "br0.30" {
		t.Fatal("compiled VAP interfaces or VLAN bridges are not distinct")
	}
	if compiled.System["netconf.3.devname"] != "ath0" || compiled.System["netconf.5.devname"] != "ath2" {
		t.Fatal("compiled VAP netconf records are incomplete")
	}
	if compiled.System["connectivity.status"] != "disabled" || compiled.System["connectivity.uplink_eth"] != "" || compiled.System["connectivity.uplink_bridge"] != "" || compiled.System["dhcpc.1.devname"] != "br0" || compiled.System["iptables.status"] != "disabled" || compiled.System["system.timezone"] != "UTC0" {
		t.Fatal("compiled generic AP subsystem defaults are incomplete")
	}
	if compiled.System["ntpclient.status"] != "disabled" || compiled.System["switch.jumboframes"] != "disabled" || compiled.System["switch.jumboframes.status"] != "" {
		t.Fatal("compiled NTP or jumbo-frame defaults are incorrect")
	}
	if compiled.System["wireless.2.beacon_rate"] != "1000" || compiled.System["wireless.1.dtim_period"] != "3" || compiled.System["ebtables.1.cmd"] == "" {
		t.Fatal("compiled band or VAP defaults are incomplete")
	}
	if len(compiled.System["aaa.1.iapp_key"]) != 32 || !strings.HasPrefix(compiled.System["users.1.password"], "$6$") {
		t.Fatal("compiled credential encodings are incorrect")
	}
	if err := sha512_crypt.New().Verify(compiled.System["users.1.password"], []byte("fixture-passphrase")); err != nil {
		t.Fatal("compiled SSH password hash does not verify")
	}
	repeated, err := ap.New().Compile(descriptor, config, fileSecrets{})
	if err != nil || repeated.Version != compiled.Version || repeated.System["users.1.password"] != compiled.System["users.1.password"] {
		t.Fatal("repeated compilation is not deterministic")
	}
	unused := config
	unused.Networks = config.Networks[1:]
	unused.Radios = append([]network.RadioConfig(nil), config.Radios...)
	unused.Radios[0].WidthMHz = network.Width40
	unusedChannel := uint16(6)
	unused.Radios[0].Channel = &unusedChannel
	unused.Radios[1].Enabled = false
	unusedCompiled, err := ap.New().Compile(descriptor, unused, fileSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	if unusedCompiled.System["radio.1.devname"] == unusedCompiled.System["radio.2.devname"] || unusedCompiled.System["radio.1.devname"] == unusedCompiled.System["wireless.1.devname"] || unusedCompiled.System["radio.2.devname"] != unusedCompiled.System["wireless.1.devname"] {
		t.Fatal("unused radio and VAP interfaces are not unique")
	}
	if unusedCompiled.System["radio.1.cwm.mode"] != "0" || unusedCompiled.System["radio.2.cwm.mode"] != "1" {
		t.Fatal("band-specific 40 MHz encoding is incorrect")
	}
	physicalDescriptor := descriptor
	var uplinkReport informmodel.Report
	if err := json.Unmarshal([]byte(`{"type":"uap","uplink":"eth1","radio_table":[{"name":"wifi0","radio":"ng"}],"port_table":[{"port_idx":1,"ifname":"eth0"},{"port_idx":2,"ifname":"eth1"}]}`), &uplinkReport); err != nil {
		t.Fatal(err)
	}
	uplinkDescriptor, err := profile.Describe(uplinkReport)
	if err != nil || uplinkDescriptor.UplinkInterface != "eth1" {
		t.Fatal("descriptor did not preserve the reported uplink")
	}
	physicalDescriptor.Radios = append([]profile.RadioCapability(nil), descriptor.Radios...)
	physicalDescriptor.Radios[0].Interface = "wifi0"
	physicalDescriptor.Radios[1].Interface = "wifi1"
	physicalDescriptor.UplinkInterface = "eth1"
	physicalDescriptor.Ports = []profile.PortCapability{
		{Index: 1, Interface: "eth0", VLAN: nil, PoEModes: nil},
		{Index: 2, Interface: "eth1", VLAN: nil, PoEModes: nil},
	}
	physicalConfig := config
	physicalConfig.Networks = config.Networks[:1]
	physicalCompiled, err := ap.New().Compile(physicalDescriptor, physicalConfig, fileSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	if physicalCompiled.System["radio.1.devname"] != "wifi0ap0" || physicalCompiled.System["wireless.1.devname"] != "wifi0ap0" || physicalCompiled.System["radio.2.devname"] != "wifi1ap1" || physicalCompiled.System["wireless.2.devname"] != "wifi1ap1" {
		t.Fatal("physical-shaped interfaces did not use phy-derived VAP names")
	}
	if physicalCompiled.System["connectivity.status"] != "enabled" || physicalCompiled.System["connectivity.uplink_eth"] != "eth1" {
		t.Fatal("physical connectivity did not use the reported uplink")
	}
	physicalMultiCompiled, err := ap.New().Compile(physicalDescriptor, config, fileSecrets{})
	if err != nil {
		t.Fatal(err)
	}
	if physicalMultiCompiled.System["radio.1.virtual.1.devname"] != "wifi0ap1" || physicalMultiCompiled.System["radio.1.virtual.1.mode"] != "master" || physicalMultiCompiled.System["radio.2.devname"] != "wifi1ap2" {
		t.Fatal("physical multi-VAP radio mappings are incomplete")
	}
	badDescriptor := descriptor
	badDescriptor.Radios = append([]profile.RadioCapability(nil), descriptor.Radios...)
	badDescriptor.Radios[0].Interface = "bad\ninterface"
	if _, err := ap.New().Compile(badDescriptor, config, fileSecrets{}); err == nil {
		t.Fatal("newline in a reported interface was accepted")
	}
	for _, pair := range []struct {
		band    network.RadioBand
		channel uint16
		width   network.ChannelWidthMHz
	}{
		{network.Band2GHz, 0, network.Width20},
		{network.Band2GHz, 6, network.Width20},
		{network.Band2GHz, 11, network.Width20},
		{network.Band2GHz, 6, network.Width40},
		{network.Band5GHz, 0, network.Width40},
		{network.Band5GHz, 44, network.Width40},
		{network.Band5GHz, 157, network.Width40},
	} {
		requested := network.RadioConfig{Band: pair.band, Enabled: true, WidthMHz: pair.width, Power: network.PowerConfig{Mode: network.PowerAuto}}
		if pair.channel != 0 {
			requested.Channel = &pair.channel
		}
		if _, err := ap.New().Compile(descriptor, network.APConfig{CountryCode: 840, Radios: []network.RadioConfig{requested}}, nil); err != nil {
			t.Fatalf("reproduced channel/width pair was rejected: %s/%d/%d", pair.band, pair.channel, pair.width)
		}
	}
	unverifiedChannel := uint16(11)
	unverifiedPair := network.APConfig{CountryCode: 840, Radios: []network.RadioConfig{{Band: network.Band2GHz, Enabled: true, Channel: &unverifiedChannel, WidthMHz: network.Width40, Power: network.PowerConfig{Mode: network.PowerAuto}}}}
	if _, err := ap.New().Compile(descriptor, unverifiedPair, nil); err == nil {
		t.Fatal("unreproduced channel 11 at 40 MHz was accepted without reported capability evidence")
	}
	unverifiedPair.Radios[0].Channel = nil
	if _, err := ap.New().Compile(descriptor, unverifiedPair, nil); err == nil {
		t.Fatal("unreproduced automatic channel at 40 MHz was accepted without reported width evidence")
	}
	reportedPair := descriptor
	reportedPair.Radios = []profile.RadioCapability{{ID: "ng", Interface: "wifi0", Band: network.Band2GHz, Channels: []uint16{11}, Widths: []network.ChannelWidthMHz{network.Width40}}}
	unverifiedPair.Radios[0].Channel = &unverifiedChannel
	if _, err := ap.New().Compile(reportedPair, unverifiedPair, nil); err != nil {
		t.Fatal("explicit reported channel/width evidence was restricted by the physical exception")
	}
	radioOnly := network.APConfig{CountryCode: 840, Radios: []network.RadioConfig{config.Radios[0]}}
	unfamiliar := descriptor
	unfamiliar.Model, unfamiliar.Firmware = "UnfamiliarAP", "1"
	unfamiliar.Radios = []profile.RadioCapability{{ID: "ng", Interface: "wifi0", Band: network.Band2GHz, Widths: []network.ChannelWidthMHz{network.Width20}}}
	if _, err := ap.New().Compile(unfamiliar, radioOnly, nil); err != nil {
		t.Fatal("automatic channel required an explicit channel list")
	}
	channel := uint16(6)
	radioOnly.Radios[0].Channel = &channel
	if _, err := ap.New().Compile(unfamiliar, radioOnly, nil); err == nil {
		t.Fatal("explicit channel without evidence was accepted")
	}
	unfamiliar.Radios[0].Channels = []uint16{6}
	unfamiliar.Radios[0].Widths = nil
	if _, err := ap.New().Compile(unfamiliar, radioOnly, nil); err == nil {
		t.Fatal("explicit width without evidence was accepted")
	}
	unfamiliar.Radios[0].Widths = []network.ChannelWidthMHz{network.Width20}
	power := 10
	radioOnly.Radios[0].Power = network.PowerConfig{Mode: network.PowerExplicit, DBm: &power}
	if _, err := ap.New().Compile(unfamiliar, radioOnly, nil); err == nil {
		t.Fatal("explicit power without bounds was accepted")
	}
	minimum, maximum := 0, 20
	unfamiliar.Radios[0].MinPowerDBm, unfamiliar.Radios[0].MaxPowerDBm = &minimum, &maximum
	if _, err := ap.New().Compile(unfamiliar, radioOnly, nil); err != nil {
		t.Fatal("unfamiliar model with explicit capability evidence was rejected")
	}
	var extraRadios informmodel.Report
	if err := json.Unmarshal([]byte(`{"type":"uap","radio_table":[{"name":"six","radio":"6g"},{"name":"five-a","radio":"na"},{"name":"five-b","radio":"na"}]}`), &extraRadios); err != nil {
		t.Fatal(err)
	}
	extraDescriptor, err := profile.Describe(extraRadios)
	if err != nil || len(extraDescriptor.Radios) != 3 || extraDescriptor.Radios[0].Band != "" {
		t.Fatal("unknown radio inventory was not preserved")
	}
	unfamiliar.Radios = append(unfamiliar.Radios, extraDescriptor.Radios...)
	if _, err := ap.New().Compile(unfamiliar, radioOnly, nil); err != nil {
		t.Fatal("unrequested radio inventory blocked a supported setting")
	}
	unfamiliar.Radios = append(unfamiliar.Radios, unfamiliar.Radios[0])
	if _, err := ap.New().Compile(unfamiliar, radioOnly, nil); err == nil {
		t.Fatal("ambiguous requested radio was accepted")
	}
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
