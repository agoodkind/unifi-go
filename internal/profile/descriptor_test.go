package profile

import (
	"encoding/json"
	"testing"

	"goodkind.io/unifi-go/internal/informmodel"
	"goodkind.io/unifi-go/network"
)

func TestDescribeParsesReportedRadioInventory(t *testing.T) {
	encoded := []byte(`{
		"type":"uap",
		"model":"synthetic-model",
		"version":"1.2.3",
		"ethernet_table":"eth0",
		"radio_table":[
			{"name":"wifi0","radio":"ng","channels":[1,6,11],"widths":[20,"40"],"min_txpower":6,"max_txpower":23},
			{"name":"wifi1","radio":"na","ht":"40"}
		],
		"port_table":[
			{"port_idx":1,"ifname":"eth1","poe_caps":4},
			{"port_idx":2,"ifname":"eth2","poe_caps":36}
		]
	}`)
	var report informmodel.Report
	if err := json.Unmarshal(encoded, &report); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	descriptor, err := Describe(report)
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if descriptor.Family != network.FamilyAP {
		t.Fatalf("Family = %q, want %q", descriptor.Family, network.FamilyAP)
	}
	if len(descriptor.Radios) != 2 {
		t.Fatalf("len(Radios) = %d, want 2", len(descriptor.Radios))
	}
	if report.EthernetTable.Interface != "eth0" {
		t.Fatalf("ethernet interface = %q, want eth0", report.EthernetTable.Interface)
	}
	if descriptor.Radios[0].ID != "ng" || descriptor.Radios[0].Interface != "wifi0" {
		t.Fatalf("first radio identity = %#v", descriptor.Radios[0])
	}
	if descriptor.Radios[0].Band != network.Band2GHz {
		t.Fatalf("first radio band = %q, want %q", descriptor.Radios[0].Band, network.Band2GHz)
	}
	if len(descriptor.Radios[0].Widths) != 2 || descriptor.Radios[0].Widths[1] != network.Width40 {
		t.Fatalf("first radio widths = %v, want [20 40]", descriptor.Radios[0].Widths)
	}
	if len(descriptor.Radios[1].Widths) != 0 {
		t.Fatalf("second radio widths = %v, want unknown", descriptor.Radios[1].Widths)
	}
	if len(descriptor.Ports[0].PoEModes) != 1 || descriptor.Ports[0].PoEModes[0] != network.PoEOff {
		t.Fatalf("passive port PoE modes = %v, want [off]", descriptor.Ports[0].PoEModes)
	}
	if len(descriptor.Ports[1].PoEModes) != 2 || descriptor.Ports[1].PoEModes[0] != network.PoEAuto || descriptor.Ports[1].PoEModes[1] != network.PoEOff {
		t.Fatalf("negotiated port PoE modes = %v, want [auto off]", descriptor.Ports[1].PoEModes)
	}
}
