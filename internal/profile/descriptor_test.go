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
	if descriptor.Radios[0].ID != "wifi0" || descriptor.Radios[0].Interface != "wifi0" {
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

func TestDescribeKeepsRepeatedBandRadioIDsStable(t *testing.T) {
	report := informmodel.Report{
		Type: "uap",
		RadioTable: []informmodel.Radio{
			{Name: "wifi2", Radio: "na"},
			{Name: "wifi1", Radio: "na"},
			{Name: "wifi0", Radio: "ng"},
		},
	}
	descriptor, err := Describe(report)
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{descriptor.Radios[0].ID, descriptor.Radios[1].ID, descriptor.Radios[2].ID}; !equalStrings(got, []string{"wifi2", "wifi1", "wifi0"}) {
		t.Fatalf("radio IDs = %v", got)
	}

	report.RadioTable[0], report.RadioTable[1] = report.RadioTable[1], report.RadioTable[0]
	reordered, err := Describe(report)
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{reordered.Radios[0].ID, reordered.Radios[1].ID, reordered.Radios[2].ID}; !equalStrings(got, []string{"wifi1", "wifi2", "wifi0"}) {
		t.Fatalf("reordered radio IDs = %v", got)
	}

	fallback := StableRadioIDs([]informmodel.Radio{{Radio: "ng"}, {Radio: "na"}, {Radio: "na"}, {}})
	if !equalStrings(fallback, []string{"ng", "radio-1", "radio-2", "radio-3"}) {
		t.Fatalf("fallback radio IDs = %v", fallback)
	}
	fallbackReport := informmodel.Report{Type: "uap", RadioTable: []informmodel.Radio{{Radio: "ng"}, {Radio: "na"}, {Radio: "na"}, {}}}
	fallbackDescriptor, err := Describe(fallbackReport)
	if err != nil {
		t.Fatal(err)
	}
	if fallbackDescriptor.Radios[0].SyntheticID || !fallbackDescriptor.Radios[1].SyntheticID || !fallbackDescriptor.Radios[3].SyntheticID {
		t.Fatal("synthetic radio identity classification is incorrect")
	}
	physicalDescriptor, err := Describe(informmodel.Report{Type: "uap", RadioTable: []informmodel.Radio{{Name: "radio-9", Radio: "na"}}})
	if err != nil {
		t.Fatal(err)
	}
	if physicalDescriptor.Radios[0].SyntheticID {
		t.Fatal("reported physical name was classified as a synthetic identity")
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
