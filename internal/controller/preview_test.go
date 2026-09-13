package controller_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jamesbraid/unifi-emu/inform"
	"goodkind.io/unifi-go/internal/controller"
	"goodkind.io/unifi-go/internal/profile"
	"goodkind.io/unifi-go/internal/profile/ap"
	"goodkind.io/unifi-go/network"
)

func TestPreviewTokenExpiry(t *testing.T) {
	for _, elapsed := range []time.Duration{5*time.Minute - time.Second, 5*time.Minute + time.Second} {
		t.Run(elapsed.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				state := filepath.Join(t.TempDir(), "state.json")
				device := controller.Device{MAC: testMAC, Key: testKey, Family: network.FamilyAP, Baseline: &controller.ConfigurationBaseline{
					SchemaVersion: 1, TypedReady: true,
					Config: network.Config{Version: "seed", Management: "cfgversion=seed\n", System: "unknown.policy=preserved\n"},
				}}
				data, err := json.Marshal([]controller.Device{device})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(state, data, 0o600); err != nil {
					t.Fatal(err)
				}
				c, err := controller.Open(state, testURL, profile.NewRegistry(ap.New(), nil))
				if err != nil {
					t.Fatal(err)
				}
				packet := inform.Packet{MAC: [6]byte{2, 0, 0, 0, 0, 1}, Payload: []byte(`{"model":"PreviewAP","version":"1","radio_table":[{"name":"wifi0","radio":"ng"}]}`)}
				body, err := packet.EncodeGCM(testKey)
				if err != nil {
					t.Fatal(err)
				}
				response := httptest.NewRecorder()
				c.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/inform", bytes.NewReader(body)))
				if response.Code != http.StatusOK {
					t.Fatal("authenticated report failed")
				}
				config := network.APConfig{}
				previewResponse := callPreviewControl(t, c, controller.ControlRequest{Operation: "preview-ap", Device: testMAC, AP: &config})
				var previewEnvelope struct {
					Preview network.ConfigPreview `json:"preview"`
				}
				if previewResponse.Code != http.StatusOK || json.Unmarshal(previewResponse.Body.Bytes(), &previewEnvelope) != nil || previewEnvelope.Preview.Token == "" {
					t.Fatal("preview failed")
				}
				if previewEnvelope.Preview.Added != 2 || previewEnvelope.Preview.Changed != 1 || previewEnvelope.Preview.Removed != 0 {
					t.Fatal("preview did not count injected management records")
				}
				before, err := os.ReadFile(state)
				if err != nil {
					t.Fatal(err)
				}
				time.Sleep(elapsed)
				applied := callPreviewControl(t, c, controller.ControlRequest{Operation: "apply-ap", Device: testMAC, AP: &config, PreviewToken: previewEnvelope.Preview.Token})
				if elapsed < 5*time.Minute {
					if applied.Code != http.StatusOK || c.Status()[0].Pending != 1 {
						t.Fatal("unexpired preview did not apply")
					}
					return
				}
				var failure struct {
					Error *network.ControlError `json:"error"`
				}
				if applied.Code != http.StatusBadRequest || json.Unmarshal(applied.Body.Bytes(), &failure) != nil || failure.Error == nil || failure.Error.Code != network.PreviewStale {
					t.Fatal("expired token was not rejected")
				}
				after, err := os.ReadFile(state)
				if err != nil || !bytes.Equal(before, after) || c.Status()[0].Pending != 0 {
					t.Fatal("expired token changed state or queue")
				}
			})
		})
	}
}

func callPreviewControl(t *testing.T, c *controller.Controller, request controller.ControlRequest) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	c.Control(response, httptest.NewRequest(http.MethodPost, "/control", bytes.NewReader(body)))
	return response
}
