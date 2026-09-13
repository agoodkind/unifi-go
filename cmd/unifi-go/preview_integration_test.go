package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jamesbraid/unifi-emu/inform"
	"goodkind.io/unifi-go/internal/controller"
	"goodkind.io/unifi-go/internal/informmodel"
	"goodkind.io/unifi-go/network"
)

const (
	previewTestKey                  = "0123456789abcdef0123456789abcdef" // gitleaks:allow
	previewTestID  network.DeviceID = "02:00:00:00:00:61"
)

type previewFixture struct {
	controller *controller.Controller
	client     *network.Client
	state      string
	secret     string
	config     network.APConfig
	report     informmodel.Report
}

func newPreviewFixture(t *testing.T) previewFixture {
	t.Helper()
	directory := t.TempDir()
	state := filepath.Join(directory, "state.json")
	secret := filepath.Join(directory, "credential")
	writeTypedFixture(t, secret, []byte("documentation-only-password"))
	writeTypedJSON(t, state, []controller.Device{{MAC: string(previewTestID), Key: previewTestKey, Baseline: typedSeedBaseline(t, network.FamilyAP, "seed")}})
	c := openTypedController(t, state)
	report := informmodel.Report{Model: "DocumentationAP", Version: "1", RadioTable: []informmodel.Radio{{Name: "wifi0", Radio: "ng", Widths: []informmodel.Uint16Scalar{20}}}}
	typedExchange(t, c, previewTestID, previewTestKey, report, true)
	return previewFixture{controller: c, client: network.Dial(startTypedSocket(t, c)), state: state, secret: secret, config: typedAPFixture(secret), report: report}
}

func previewStateBytes(t *testing.T, state string) []byte {
	t.Helper()
	data, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func previewPersistedDevice(t *testing.T, state string) controller.Device {
	t.Helper()
	var records []controller.Device
	if err := json.Unmarshal(previewStateBytes(t, state), &records); err != nil || len(records) != 1 {
		t.Fatal("cannot read persisted transaction")
	}
	return records[0]
}

func typedPersistedReply(t *testing.T, state string, id network.DeviceID) controller.Reply {
	t.Helper()
	var records []controller.Device
	if err := json.Unmarshal(previewStateBytes(t, state), &records); err != nil {
		t.Fatal("cannot read persisted typed configuration")
	}
	for _, device := range records {
		if device.MAC == string(id) && device.LastSetParam != nil {
			return *device.LastSetParam
		}
	}
	t.Fatal("persisted typed configuration is absent")
	return controller.Reply{}
}

func testPreviewTransaction(t *testing.T) {
	t.Run("stale inputs", testPreviewStaleInputs)
	t.Run("concurrent callers", testPreviewConcurrentCallers)
	t.Run("persistence rollback", testPreviewPersistenceRollback)
	t.Run("representation and restart", testPreviewRepresentationRestart)
	t.Run("unrequested SSH policy", testPreviewUnrequestedSSH)
	const key = "0123456789abcdef0123456789abcdef" // gitleaks:allow
	const id network.DeviceID = "02:00:00:00:00:61"
	directory := t.TempDir()
	state := filepath.Join(directory, "state.json")
	secretPath := filepath.Join(directory, "credential")
	writeTypedFixture(t, secretPath, []byte("documentation-only-password"))
	writeTypedJSON(t, state, []controller.Device{{MAC: string(id), Key: key, Baseline: typedSeedBaseline(t, network.FamilyAP, "seed")}})
	c := openTypedController(t, state)
	client := network.Dial(startTypedSocket(t, c))
	report := informmodel.Report{Model: "DocumentationAP", Version: "1", RadioTable: []informmodel.Radio{{Name: "wifi0", Radio: "ng", Widths: []informmodel.Uint16Scalar{20}}}}
	typedExchange(t, c, id, key, report, true)
	config := typedAPFixture(secretPath)
	before, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := client.PreviewAP(t.Context(), id, config)
	if err != nil || preview.Token == "" || preview.Added == 0 {
		t.Fatal("preview did not return an opaque token and record counts")
	}
	after, err := os.ReadFile(state)
	if err != nil || !bytes.Equal(before, after) || c.Status()[0].Pending != 0 {
		t.Fatal("preview changed state or queued work")
	}
	if reply := typedExchange(t, c, id, key, report, true); reply.Type != controller.ReplyNoop {
		t.Fatal("preview delivered configuration")
	}
	version, err := client.ApplyAPPreview(t.Context(), id, config, preview.Token)
	if err != nil || version == "" {
		t.Fatal("previewed configuration was not queued")
	}
	if reply := typedExchange(t, c, id, key, report, true); reply.Type != controller.ReplySetparam || reply.ConfigVersion != string(version) {
		t.Fatal("previewed configuration was not delivered")
	}
	_, err = client.ApplyAP(t.Context(), id, config)
	assertControlFailure(t, err, network.ConfigurationPending, "")
	report.ConfigVersion = string(version)
	forgedPayload, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	packet := inform.Packet{MAC: [6]byte{2, 0, 0, 0, 0, 0x61}, Payload: forgedPayload}
	forgedBody, err := packet.EncodeGCM("fedcba9876543210fedcba9876543210") // gitleaks:allow
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	c.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/inform", bytes.NewReader(forgedBody)))
	if response.Code != http.StatusBadRequest {
		t.Fatal("unauthenticated matching report was accepted")
	}
	_, err = client.ApplyAP(t.Context(), id, config)
	assertControlFailure(t, err, network.ConfigurationPending, "")
	typedExchange(t, c, id, key, report, true)
	if _, err := client.ApplyAP(t.Context(), id, config); err != nil || c.Status()[0].Pending != 0 {
		t.Fatal("unchanged acknowledged configuration queued work")
	}
	unchanged, err := client.PreviewAP(t.Context(), id, config)
	if err != nil || unchanged.Added != 0 || unchanged.Changed != 0 || unchanged.Removed != 0 {
		t.Fatal("unchanged preview reported record changes")
	}
}

func testPreviewUnrequestedSSH(t *testing.T) {
	fixture := newPreviewFixture(t)
	fixture.config.SSH = network.Supplied(network.SSHConfig{Username: network.Supplied("operator"), Password: network.Supplied(network.SecretFile(fixture.secret))}) // gitleaks:allow -- temporary fixture file reference
	version, err := fixture.client.ApplyAP(t.Context(), previewTestID, fixture.config)
	if err != nil {
		t.Fatal("initial SSH apply failed")
	}
	typedExchange(t, fixture.controller, previewTestID, previewTestKey, fixture.report, true)
	fixture.report.ConfigVersion = string(version)
	typedExchange(t, fixture.controller, previewTestID, previewTestKey, fixture.report, true)
	device := previewPersistedDevice(t, fixture.state)
	const importedHash = "$y$imported$opaque" // gitleaks:allow
	device.Baseline.Config.System = strings.ReplaceAll(device.Baseline.Config.System, device.SSHPasswordHash, importedHash)
	if err := fixture.client.ImportBaseline(t.Context(), previewTestID, network.BaselineImport{Config: device.Baseline.Config, AP: device.DesiredAP}); err != nil {
		t.Fatal("complete SSH baseline import failed")
	}
	request := network.APConfig{CountryCode: network.Supplied(uint16(124))}
	preview, err := fixture.client.PreviewAP(t.Context(), previewTestID, request)
	if err != nil {
		t.Fatal("unrequested SSH policy prevented preview")
	}
	if _, err := fixture.client.ApplyAPPreview(t.Context(), previewTestID, request, preview.Token); err != nil {
		t.Fatal("unrequested SSH policy prevented apply")
	}
	reply := typedExchange(t, fixture.controller, previewTestID, previewTestKey, fixture.report, true)
	if !strings.Contains(reply.SystemConfig, "users.1.password="+importedHash) || !strings.Contains(reply.SystemConfig, "radio.countrycode=124") { // gitleaks:allow -- synthetic imported hash assertion
		t.Fatal("unrelated apply did not preserve imported SSH policy")
	}
}

func testPreviewStaleInputs(t *testing.T) {
	for _, change := range []string{"baseline", "capabilities", "request", "secret", "unreadable secret", "restart", "unknown token"} {
		t.Run(change, func(t *testing.T) {
			fixture := newPreviewFixture(t)
			preview, err := fixture.client.PreviewAP(t.Context(), previewTestID, fixture.config)
			if err != nil {
				t.Fatal("preview failed")
			}
			switch change {
			case "baseline":
				baseline := typedSeedBaseline(t, network.FamilyAP, "reimported")
				baseline.Config.System += "unknown.policy=preserved\n"
				if err := fixture.client.ImportBaseline(t.Context(), previewTestID, network.BaselineImport{Config: baseline.Config}); err != nil {
					t.Fatal("baseline import failed")
				}
			case "capabilities":
				fixture.report.RadioTable[0].Widths = []informmodel.Uint16Scalar{20, 40}
				typedExchange(t, fixture.controller, previewTestID, previewTestKey, fixture.report, true)
			case "request":
				fixture.config.Networks.Value[0].BSSTransition = network.Supplied(network.BSSTransitionDisabled)
			case "secret":
				writeTypedFixture(t, fixture.secret, []byte("changed-documentation-password"))
			case "unreadable secret":
				if err := os.Remove(fixture.secret); err != nil {
					t.Fatal(err)
				}
			case "restart":
				fixture.controller = openTypedController(t, fixture.state)
				fixture.client = network.Dial(startTypedSocket(t, fixture.controller))
			case "unknown token":
				preview.Token = "unknown"
			}
			before := previewStateBytes(t, fixture.state)
			_, err = fixture.client.ApplyAPPreview(t.Context(), previewTestID, fixture.config, preview.Token)
			assertControlFailure(t, err, network.PreviewStale, "")
			if !bytes.Equal(before, previewStateBytes(t, fixture.state)) || fixture.controller.Status()[0].Pending != 0 {
				t.Fatal("stale preview mutated persisted state or queue")
			}
			if reply := typedExchange(t, fixture.controller, previewTestID, previewTestKey, fixture.report, true); reply.Type != controller.ReplyNoop {
				t.Fatal("stale preview delivered configuration")
			}
		})
	}
}

func testPreviewConcurrentCallers(t *testing.T) {
	fixture := newPreviewFixture(t)
	start := make(chan struct{})
	type result struct {
		version network.ConfigVersion
		err     error
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			<-start
			version, err := fixture.client.ApplyAP(t.Context(), previewTestID, fixture.config)
			results <- result{version: version, err: err}
		}()
	}
	close(start)
	var committed network.ConfigVersion
	successes := 0
	for range 2 {
		outcome := <-results
		if outcome.err == nil {
			successes++
			committed = outcome.version
		} else {
			assertControlFailure(t, outcome.err, network.ConfigurationPending, "")
		}
	}
	if successes != 1 || fixture.controller.Status()[0].Pending != 1 || previewPersistedDevice(t, fixture.state).DesiredVersion != committed {
		t.Fatal("concurrent callers did not produce exactly one persisted transition")
	}
	if reply := typedExchange(t, fixture.controller, previewTestID, previewTestKey, fixture.report, true); reply.ConfigVersion != string(committed) {
		t.Fatal("queued transition differs from persisted transition")
	}
	_, err := fixture.client.PreviewAP(t.Context(), previewTestID, fixture.config)
	assertControlFailure(t, err, network.ConfigurationPending, "")
}

func testPreviewPersistenceRollback(t *testing.T) {
	fixture := newPreviewFixture(t)
	preview, err := fixture.client.PreviewAP(t.Context(), previewTestID, fixture.config)
	if err != nil {
		t.Fatal("preview failed")
	}
	before := previewStateBytes(t, fixture.state)
	backup := fixture.state + ".saved"
	if err := os.Rename(fixture.state, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(fixture.state, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err = fixture.client.ApplyAPPreview(t.Context(), previewTestID, fixture.config, preview.Token)
	assertControlFailure(t, err, network.PersistenceFailed, "")
	if fixture.controller.Status()[0].Pending != 0 || !bytes.Equal(before, previewStateBytes(t, backup)) {
		t.Fatal("failed persistence queued work or changed prior state")
	}
	snapshot, err := fixture.client.Device(t.Context(), previewTestID)
	if err != nil || snapshot.DesiredConfigVersion != "" || snapshot.LastSetParamVersion != "" {
		t.Fatal("failed persistence changed in-memory configuration")
	}
	if err := os.Remove(fixture.state); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(backup, fixture.state); err != nil {
		t.Fatal(err)
	}
	if reply := typedExchange(t, fixture.controller, previewTestID, previewTestKey, fixture.report, true); reply.Type != controller.ReplyNoop {
		t.Fatal("failed persistence delivered configuration")
	}
	if _, err := fixture.client.ApplyAPPreview(t.Context(), previewTestID, fixture.config, preview.Token); err != nil {
		t.Fatal("failed transaction did not roll back baseline or retain retryable token")
	}
}

func testPreviewRepresentationRestart(t *testing.T) {
	fixture := newPreviewFixture(t)
	version, err := fixture.client.ApplyAP(t.Context(), previewTestID, fixture.config)
	if err != nil {
		t.Fatal("initial apply failed")
	}
	typedExchange(t, fixture.controller, previewTestID, previewTestKey, fixture.report, true)
	fixture.report.ConfigVersion = string(version)
	typedExchange(t, fixture.controller, previewTestID, previewTestKey, fixture.report, true)
	newSecret := fixture.secret + ".equivalent"
	writeTypedFixture(t, newSecret, previewStateBytes(t, fixture.secret))
	fixture.config.Networks.Value[0].Security.Value.PSK = network.Supplied(network.SecretFile(newSecret))
	unchanged, err := fixture.client.ApplyAP(t.Context(), previewTestID, fixture.config)
	if err != nil || unchanged != version || fixture.controller.Status()[0].Pending != 0 {
		t.Fatal("equivalent representation queued configuration or changed its version")
	}
	device := previewPersistedDevice(t, fixture.state)
	if device.DesiredAP == nil || device.DesiredAP.Networks.Value[0].Security.Value.PSK.Value != network.SecretFile(newSecret) {
		t.Fatal("equivalent representation was not persisted")
	}
	fixture.config.Networks.Value[0].BSSTransition = network.Supplied(network.BSSTransitionDisabled)
	pendingVersion, err := fixture.client.ApplyAP(t.Context(), previewTestID, fixture.config)
	if err != nil {
		t.Fatal("unchanged apply incorrectly set awaiting state")
	}
	fixture.controller = openTypedController(t, fixture.state)
	fixture.client = network.Dial(startTypedSocket(t, fixture.controller))
	_, err = fixture.client.ApplyAP(t.Context(), previewTestID, fixture.config)
	assertControlFailure(t, err, network.NoReport, "")
	if reply := typedExchange(t, fixture.controller, previewTestID, previewTestKey, fixture.report, true); reply.Type != controller.ReplyNoop {
		t.Fatal("restart replayed pending work")
	}
	retriedVersion, err := fixture.client.ApplyAP(t.Context(), previewTestID, fixture.config)
	if err != nil || retriedVersion != pendingVersion || fixture.controller.Status()[0].Pending != 1 {
		t.Fatal("same desired configuration was not requeued after restart with an older report")
	}
	retriedReply := typedExchange(t, fixture.controller, previewTestID, previewTestKey, fixture.report, true)
	if retriedReply.Type != controller.ReplySetparam || retriedReply.ConfigVersion != string(pendingVersion) || !strings.Contains(retriedReply.SystemConfig, "aaa.1.bss_transition=disabled") {
		t.Fatal("restart retry did not deliver the persisted desired configuration")
	}
	fixture.report.ConfigVersion = string(pendingVersion)
	typedExchange(t, fixture.controller, previewTestID, previewTestKey, fixture.report, true)
	if version, err := fixture.client.ApplyAP(t.Context(), previewTestID, fixture.config); err != nil || version != pendingVersion || fixture.controller.Status()[0].Pending != 0 {
		t.Fatal("acknowledged retry queued unchanged configuration")
	}
	fixture.config.Networks.Value[0].BSSTransition = network.Supplied(network.BSSTransitionEnabled)
	if _, err := fixture.client.ApplyAP(t.Context(), previewTestID, fixture.config); err != nil {
		t.Fatal("fresh report did not allow full reconciliation after restart")
	}
	reply := typedExchange(t, fixture.controller, previewTestID, previewTestKey, fixture.report, true)
	if reply.Type != controller.ReplySetparam || !bytes.Contains([]byte(reply.SystemConfig), []byte("aaa.1.bss_transition=enabled")) {
		t.Fatal("restart composition did not deliver requested policy")
	}
}
