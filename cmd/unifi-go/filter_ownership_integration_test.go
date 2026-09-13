package main

import (
	"bytes"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"goodkind.io/unifi-go/internal/configmap"
	"goodkind.io/unifi-go/internal/controller"
	"goodkind.io/unifi-go/internal/informmodel"
	"goodkind.io/unifi-go/network"
)

func TestBaselineImportRejectsMixedFilterOwnership(t *testing.T) {
	inputs := []string{"--in-interface ath0", "-i ath0", "--in-interface=ath0", "-iath0"}
	outputs := []string{"--out-interface ath2", "-o ath2", "--out-interface=ath2", "-oath2"}
	for _, input := range inputs {
		for _, output := range outputs {
			for _, projected := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/projected=%t", input, output, projected), func(t *testing.T) {
					config, baseline := typedBSSFixture(t, "unused-fixture-secret", "imported")
					if !projected {
						config.Networks.Value = config.Networks.Value[:1]
					}
					baseline.Config.System += "ebtables.99.cmd=-A FORWARD " + input + " " + output + " -j ACCEPT\n"
					state := filepath.Join(t.TempDir(), "state.json")
					writeTypedJSON(t, state, []controller.Device{{MAC: string(previewTestID), Key: previewTestKey}})
					c := openTypedController(t, state)
					client := network.Dial(startTypedSocket(t, c))
					report := informmodel.Report{Type: "uap", RadioTable: []informmodel.Radio{{Name: "wifi0", Radio: "ng"}, {Name: "wifi1", Radio: "na"}}}
					typedExchange(t, c, previewTestID, previewTestKey, report, true)
					before := previewStateBytes(t, state)
					err := client.ImportBaseline(t.Context(), previewTestID, network.BaselineImport{Config: baseline.Config, AP: &config})
					assertControlFailure(t, err, network.BaselineUnusable, "")
					if !bytes.Equal(before, previewStateBytes(t, state)) || c.Status()[0].Pending != 0 {
						t.Fatal("ambiguous filter ownership changed state or queued work")
					}
					if reply := typedExchange(t, c, previewTestID, previewTestKey, report, true); reply.Type != controller.ReplyNoop {
						t.Fatal("ambiguous filter import delivered configuration")
					}
				})
			}
		}
	}
}

func TestFilterSyntaxSurvivesCopyAndRemoval(t *testing.T) {
	for _, selector := range []string{
		"-i %s", "-o %s", "--in-interface %s", "--out-interface %s",
		"--in-interface=%s", "--out-interface=%s", "-i%s", "-o%s",
		"-i %[1]s --out-interface=%[1]s", "--in-interface %s -o eth0",
		"--in-interface %s --comment=issue#123", "--in-interface %s --comment issue#123",
		"--in-interface %s --comment=#123", "--in-interface %s --comment issue\u00a0#123",
		"-i %s --out-interface=ath2\u00a0#123", "-iath2\u2003#123 --out-interface=%s",
		"-i %[1]s -o ath2\u202f#123 --in-interface=%[1]s",
	} {
		t.Run(selector, func(t *testing.T) {
			config, baseline := typedBSSFixture(t, "unused-fixture-secret", "imported")
			command := "-t nat  -A PREROUTING\t" + fmt.Sprintf(selector, "ath2") + "  -j DROP"
			baseline.Config.System += "ebtables.99.cmd=" + command + "\nebtables.99.operator.unmodeled=owned-filter\nebtables.98.cmd=-A FORWARD -i ath4 -j ACCEPT\n"
			before, err := configmap.Parse(baseline.Config.System)
			if err != nil {
				t.Fatal("cannot parse filter fixture")
			}
			state := filepath.Join(t.TempDir(), "state.json")
			writeTypedJSON(t, state, []controller.Device{{MAC: string(previewTestID), Key: previewTestKey}})
			c := openTypedController(t, state)
			client := network.Dial(startTypedSocket(t, c))
			report := informmodel.Report{Type: "uap", RadioTable: []informmodel.Radio{{Name: "wifi0", Radio: "ng"}, {Name: "wifi1", Radio: "na"}}}
			typedExchange(t, c, previewTestID, previewTestKey, report, true)
			if err := client.ImportBaseline(t.Context(), previewTestID, network.BaselineImport{Config: baseline.Config, AP: &config}); err != nil {
				t.Fatal("unambiguous filter import failed")
			}
			request := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{
				{Name: "fixture-legacy"},
				{Name: "fixture-enabled", Bands: network.Supplied([]network.RadioBand{network.Band2GHz, network.Band5GHz})},
				{Name: "fixture-disabled"},
				{Name: "fixture-absent"},
			})}
			version, err := client.ApplyAP(t.Context(), previewTestID, request)
			if err != nil {
				t.Fatal("filter copy failed")
			}
			delivered := typedExchange(t, c, previewTestID, previewTestKey, report, true)
			after, err := configmap.Parse(delivered.SystemConfig)
			if err != nil || delivered.Type != controller.ReplySetparam {
				t.Fatal("filter copy was not delivered")
			}
			for key, value := range before {
				if after[key] != value {
					t.Fatal("filter copy changed an existing record")
				}
			}
			persisted := previewPersistedDevice(t, state)
			var copiedInterface string
			for _, binding := range persisted.Baseline.Bindings {
				if binding.Kind == "wifi" && binding.Identity == "fixture-enabled" && binding.RadioID == "wifi1" {
					copiedInterface = after[binding.Prefixes[0]+"devname"]
				}
			}
			if copiedInterface == "" || copiedInterface == "ath2" {
				t.Fatal("copied WiFi interface is missing")
			}
			expected := "-t nat  -A PREROUTING\t" + fmt.Sprintf(selector, copiedInterface) + "  -j DROP"
			copied := 0
			for key, value := range after {
				if value == "owned-filter" && key != "ebtables.99.operator.unmodeled" {
					prefix := strings.TrimSuffix(key, "operator.unmodeled")
					if after[prefix+"cmd"] != expected {
						t.Fatal("copied filter syntax or interface reference changed incorrectly")
					}
					copied++
				}
			}
			if copied != 1 {
				t.Fatal("owned filter was not copied exactly once")
			}
			report.ConfigVersion = string(version)
			typedExchange(t, c, previewTestID, previewTestKey, report, true)
			request.Networks.Value = []network.WiFiNetwork{{Name: "fixture-legacy"}, {Name: "fixture-disabled"}, {Name: "fixture-absent"}}
			if _, err := client.ApplyAP(t.Context(), previewTestID, request); err != nil {
				t.Fatal("owned filter removal failed")
			}
			removed := typedExchange(t, c, previewTestID, previewTestKey, report, true)
			values, err := configmap.Parse(removed.SystemConfig)
			if err != nil || removed.Type != controller.ReplySetparam {
				t.Fatal("filter removal was not delivered")
			}
			for _, value := range values {
				if value == "owned-filter" {
					t.Fatal("removed WiFi retained an owned filter")
				}
			}
			if values["ebtables.98.cmd"] != before["ebtables.98.cmd"] || maps.Equal(after, values) {
				t.Fatal("filter removal changed unrelated policy or did not remove the resource")
			}
		})
	}
}

func TestFilterUnicodeWhitespacePreservesOwnership(t *testing.T) {
	for _, whitespace := range []rune{
		'\v', '\f', '\u0085', '\u00a0', '\u1680', '\u2000', '\u2001', '\u2002',
		'\u2003', '\u2004', '\u2005', '\u2006', '\u2007', '\u2008', '\u2009',
		'\u200a', '\u2028', '\u2029', '\u202f', '\u205f', '\u3000',
	} {
		for _, selector := range []string{
			"-i %s", "-o %s", "--in-interface %s", "--out-interface %s",
			"--in-interface=%s", "--out-interface=%s", "-i%s", "-o%s",
		} {
			for _, operation := range []string{"import", "copy", "remove"} {
				t.Run(fmt.Sprintf("U+%04X/%s/%s", whitespace, selector, operation), func(t *testing.T) {
					command := "-A FORWARD " + fmt.Sprintf(selector, "ath2"+string(whitespace)+"#123") + " -j DROP"
					checkLiteralFilterOwnership(t, command, operation)
				})
			}
		}
	}
}

func checkLiteralFilterOwnership(t *testing.T, command, operation string) {
	t.Helper()
	config, baseline := typedBSSFixture(t, "unused-fixture-secret", "imported")
	baseline.Config.System += "ebtables.99.cmd=" + command + "\nebtables.99.operator.unmodeled=unowned-filter\n"
	before, err := configmap.Parse(baseline.Config.System)
	if err != nil {
		t.Fatal("cannot parse literal filter fixture")
	}
	device := controller.Device{MAC: string(previewTestID), Key: previewTestKey}
	if operation != "import" {
		device.Baseline, device.DesiredAP, device.DesiredVersion = baseline, &config, baseline.Config.Version
	}
	state := filepath.Join(t.TempDir(), "state.json")
	writeTypedJSON(t, state, []controller.Device{device})
	c := openTypedController(t, state)
	client := network.Dial(startTypedSocket(t, c))
	report := informmodel.Report{Type: "uap", ConfigVersion: string(baseline.Config.Version), RadioTable: []informmodel.Radio{{Name: "wifi0", Radio: "ng"}, {Name: "wifi1", Radio: "na"}}}
	typedExchange(t, c, previewTestID, previewTestKey, report, true)
	if operation == "import" {
		if err := client.ImportBaseline(t.Context(), previewTestID, network.BaselineImport{Config: baseline.Config, AP: &config}); err != nil {
			t.Fatal("literal selector import failed")
		}
		for _, binding := range previewPersistedDevice(t, state).Baseline.Bindings {
			if slices.Contains(binding.Prefixes, "ebtables.99.") {
				t.Fatal("literal selector acquired WiFi ownership")
			}
		}
		if c.Status()[0].Pending != 0 || typedExchange(t, c, previewTestID, previewTestKey, report, true).Type != controller.ReplyNoop {
			t.Fatal("literal selector import queued configuration")
		}
		return
	}
	request := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{{Name: "fixture-legacy"}, {Name: "fixture-disabled"}, {Name: "fixture-absent"}})}
	expectedCopies := 0
	if operation == "copy" {
		request.Networks.Value = append(request.Networks.Value, network.WiFiNetwork{Name: "fixture-enabled", Bands: network.Supplied([]network.RadioBand{network.Band2GHz, network.Band5GHz})})
		expectedCopies = 2
	}
	if _, err := client.ApplyAP(t.Context(), previewTestID, request); err != nil {
		t.Fatal("literal selector blocked the resource mutation")
	}
	reply := typedExchange(t, c, previewTestID, previewTestKey, report, true)
	after, err := configmap.Parse(reply.SystemConfig)
	if err != nil || reply.Type != controller.ReplySetparam {
		t.Fatal("resource mutation was not delivered")
	}
	filters, copies := 0, 0
	for key, value := range after {
		if strings.HasPrefix(key, "ebtables.") {
			if original, found := before[key]; !found || value != original {
				t.Fatal("resource mutation copied or rewrote an unowned filter")
			}
			filters++
		}
		if strings.HasPrefix(key, "wireless.") && strings.HasSuffix(key, ".ssid") && value == "fixture-enabled" {
			copies++
		}
	}
	for key, value := range before {
		if strings.HasPrefix(key, "ebtables.") {
			if after[key] != value {
				t.Fatal("resource mutation removed an unowned filter")
			}
			filters--
		}
		if operation == "copy" && after[key] != value {
			t.Fatal("resource copy changed an existing record")
		}
	}
	if filters != 0 || copies != expectedCopies {
		t.Fatal("resource mutation did not preserve filters and change the selected WiFi")
	}
}

func TestBaselineImportRejectsUnprovableFilterSelectors(t *testing.T) {
	for _, selector := range []string{"-i", "-i -j ACCEPT", "--in-interface=", "-i ! ath0", "--in-interface ath+", "--in-interface=\"ath0\""} {
		t.Run(selector, func(t *testing.T) {
			config, baseline := typedBSSFixture(t, "unused-fixture-secret", "imported")
			baseline.Config.System += "ebtables.99.cmd=-A FORWARD " + selector + "\n"
			state := filepath.Join(t.TempDir(), "state.json")
			writeTypedJSON(t, state, []controller.Device{{MAC: string(previewTestID), Key: previewTestKey}})
			c := openTypedController(t, state)
			client := network.Dial(startTypedSocket(t, c))
			report := informmodel.Report{Type: "uap", RadioTable: []informmodel.Radio{{Name: "wifi0", Radio: "ng"}, {Name: "wifi1", Radio: "na"}}}
			typedExchange(t, c, previewTestID, previewTestKey, report, true)
			before := previewStateBytes(t, state)
			err := client.ImportBaseline(t.Context(), previewTestID, network.BaselineImport{Config: baseline.Config, AP: &config})
			assertControlFailure(t, err, network.BaselineUnusable, "")
			if !bytes.Equal(before, previewStateBytes(t, state)) || c.Status()[0].Pending != 0 {
				t.Fatal("unprovable filter selector changed state or queued work")
			}
		})
	}
}

func TestFilterCommentsRejectImportCopyAndRemoval(t *testing.T) {
	for _, command := range []string{
		"-A FORWARD -j ACCEPT # -i ath2", "# -A FORWARD -i ath2 -j DROP",
		"-A FORWARD --comment=issue#123 -j ACCEPT\t# -i ath2",
	} {
		for _, operation := range []string{"import", "copy", "remove"} {
			t.Run(operation+"/"+command, func(t *testing.T) {
				config, baseline := typedBSSFixture(t, "unused-fixture-secret", "imported")
				baseline.Config.System += "ebtables.99.cmd=" + command + "\n"
				device := controller.Device{MAC: string(previewTestID), Key: previewTestKey}
				if operation != "import" {
					device.Baseline, device.DesiredAP, device.DesiredVersion = baseline, &config, baseline.Config.Version
				}
				state := filepath.Join(t.TempDir(), "state.json")
				writeTypedJSON(t, state, []controller.Device{device})
				c := openTypedController(t, state)
				client := network.Dial(startTypedSocket(t, c))
				report := informmodel.Report{Type: "uap", ConfigVersion: string(baseline.Config.Version), RadioTable: []informmodel.Radio{{Name: "wifi0", Radio: "ng"}, {Name: "wifi1", Radio: "na"}}}
				typedExchange(t, c, previewTestID, previewTestKey, report, true)
				before := previewStateBytes(t, state)
				var err error
				if operation == "import" {
					err = client.ImportBaseline(t.Context(), previewTestID, network.BaselineImport{Config: baseline.Config, AP: &config})
				} else {
					request := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{{Name: "fixture-legacy"}, {Name: "fixture-disabled"}, {Name: "fixture-absent"}})}
					if operation == "copy" {
						request.Networks.Value = append(request.Networks.Value, network.WiFiNetwork{Name: "fixture-enabled", Bands: network.Supplied([]network.RadioBand{network.Band2GHz, network.Band5GHz})})
					}
					_, err = client.ApplyAP(t.Context(), previewTestID, request)
					if err == nil {
						reply := typedExchange(t, c, previewTestID, previewTestKey, report, true)
						values, parseErr := configmap.Parse(reply.SystemConfig)
						if parseErr != nil {
							t.Fatal("cannot inspect the unexpectedly delivered configuration")
						}
						commented := 0
						for key, value := range values {
							if strings.HasPrefix(key, "ebtables.") && strings.HasSuffix(key, ".cmd") && strings.Contains(value, "#") {
								commented++
							}
						}
						t.Errorf("%s delivered %d commented filter records instead of rejecting ownership", operation, commented)
					}
				}
				assertControlFailure(t, err, network.BaselineUnusable, "")
				if !bytes.Equal(before, previewStateBytes(t, state)) || c.Status()[0].Pending != 0 {
					t.Fatal("commented filter changed persisted state or queued work")
				}
				if reply := typedExchange(t, c, previewTestID, previewTestKey, report, true); reply.Type != controller.ReplyNoop {
					t.Fatal("commented filter rejection delivered configuration")
				}
			})
		}
	}
}
