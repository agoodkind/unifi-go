package main

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"testing"

	"goodkind.io/unifi-go/internal/controller"
	"goodkind.io/unifi-go/internal/informmodel"
	"goodkind.io/unifi-go/network"
)

func TestPreviewErrorsDoNotLogPolicy(t *testing.T) {
	for _, family := range []network.DeviceFamily{network.FamilyAP, network.FamilySwitch} {
		t.Run(string(family), func(t *testing.T) {
			state := filepath.Join(t.TempDir(), "state.json")
			writeTypedJSON(t, state, []controller.Device{{MAC: string(previewTestID), Key: previewTestKey, Baseline: typedSeedBaseline(t, family, "seed")}})
			c := openTypedController(t, state)
			client := network.Dial(startTypedSocket(t, c))
			report := informmodel.Report{Type: "uap", RadioTable: []informmodel.Radio{{Name: "wifi0", Radio: "ng"}}}
			if family == network.FamilySwitch {
				report = informmodel.Report{Type: "usw", PortTable: []informmodel.Port{{Index: 1, Interface: "eth0"}}}
			}
			typedExchange(t, c, previewTestID, previewTestKey, report, true)
			var output bytes.Buffer
			prior := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
			t.Cleanup(func() { slog.SetDefault(prior) })
			const privatePolicy = "private-policy-marker"
			if family == network.FamilyAP {
				config := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{{Name: "fixture", BSSTransition: network.Supplied(network.BSSTransitionMode(privatePolicy))}})}
				_, err := client.PreviewAP(t.Context(), previewTestID, config)
				assertControlFailure(t, err, network.InvalidConfig, "networks[0].bss_transition")
			} else {
				config := network.SwitchConfig{Ports: network.Supplied([]network.SwitchPortConfig{{Index: 1, PoE: network.Supplied(network.PoEMode(privatePolicy))}})}
				_, err := client.PreviewSwitch(t.Context(), previewTestID, config)
				assertControlFailure(t, err, network.InvalidConfig, "ports[0].poe")
			}
			if bytes.Contains(output.Bytes(), []byte(privatePolicy)) {
				t.Fatal("preview logged rejected policy contents")
			}
			if output.Len() == 0 {
				t.Fatal("preview failure did not emit a safe diagnostic")
			}
		})
	}
}
