package controller_test

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/golang/snappy"
	"github.com/jamesbraid/unifi-emu/inform"

	"goodkind.io/unifi-go/internal/controller"
	"goodkind.io/unifi-go/internal/informmodel"
)

const (
	testMAC = "02:00:00:00:00:01"
	testKey = "0123456789abcdef0123456789abcdef"
	testURL = "http://192.0.2.3:18080/inform"
)

type reply struct {
	Type          string `json:"_type"`
	ConfigVersion string `json:"cfgversion"`
	Management    string `json:"mgmt_cfg"`
	System        string `json:"system_cfg"`
	Time          int64  `json:"server_time_in_utc"`
	Command       string `json:"cmd"`
	Key           string `json:"key"`
	URI           string `json:"uri"`
}

func setparamReply(version, management, system string) controller.Reply {
	return controller.Reply{Type: controller.ReplySetparam, Command: "", Key: "", URI: "", Interval: 0, ConfigVersion: version, ManagementConfig: management, SystemConfig: system, BlockedStations: "", ServerTime: 0}
}

func openController(t *testing.T, state string) *controller.Controller {
	t.Helper()
	c, err := controller.Open(state, testURL)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestOpenAcceptsIPv6InformURL(t *testing.T) {
	_, err := controller.Open(filepath.Join(t.TempDir(), "state.json"), "http://[2001:db8::1]:8080/inform")
	if err != nil {
		t.Fatal(err)
	}
}

func exchange(t *testing.T, endpoint, key string, gcm bool, expectedStatus int) reply {
	t.Helper()
	packet := inform.Packet{MAC: [6]byte{2, 0, 0, 0, 0, 1}, Payload: []byte(`{"cfgversion":"reported-1","model":"U7PG2","version":"6.8.2","ip":"192.0.2.10","ipv6":["2001:db8::10"],"state":2,"inform_url":"http://192.0.2.3:18080/inform","last_error":""}`)}
	var body []byte
	var err error
	if gcm {
		body, err = packet.EncodeGCM(key)
	} else {
		body, err = packet.Encode(key)
	}
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.Post(endpoint+"/inform", "application/x-binary", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != expectedStatus {
		t.Fatalf("HTTP status = %d, want %d", response.StatusCode, expectedStatus)
	}
	if expectedStatus != http.StatusOK {
		return reply{}
	}
	encoded, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := inform.Decode(encoded, key)
	if err != nil {
		t.Fatal("response does not decrypt with the device key")
	}
	if (binary.BigEndian.Uint16(encoded[14:16])&8 != 0) != gcm {
		t.Fatal("response changed the request encryption mode")
	}
	if binary.BigEndian.Uint32(encoded[4:8]) != 0 || binary.BigEndian.Uint16(encoded[14:16])&2 != 0 {
		t.Fatal("response did not use the captured controller framing")
	}
	var result reply
	if err := json.Unmarshal(decoded.Payload, &result); err != nil {
		t.Fatal(err)
	}
	if result.Time == 0 {
		t.Fatal("response omitted server time")
	}
	return result
}

func TestInformReturnsCommandsInOrderThenNoop(t *testing.T) {
	for _, gcm := range []bool{false, true} {
		t.Run(fmt.Sprintf("GCM=%t", gcm), func(t *testing.T) {
			c := openController(t, filepath.Join(t.TempDir(), "state.json"))
			if err := c.Register(testMAC, testKey); err != nil {
				t.Fatal(err)
			}
			for _, version := range []string{"first", "second"} {
				command := setparamReply(version, "cfgversion="+version+"\n", "")
				if err := c.Queue(testMAC, command); err != nil {
					t.Fatal(err)
				}
			}
			server := httptest.NewServer(c)
			defer server.Close()
			for _, version := range []string{"first", "second"} {
				result := exchange(t, server.URL, testKey, gcm, http.StatusOK)
				if result.Type != "setparam" || result.ConfigVersion != version {
					t.Fatalf("reply = %s/%s, want setparam/%s", result.Type, result.ConfigVersion, version)
				}
			}
			if result := exchange(t, server.URL, testKey, gcm, http.StatusOK); result.Type != "noop" {
				t.Fatalf("empty queue reply = %s", result.Type)
			}
			status := c.Status()
			if len(status) != 1 || status[0].Pending != 0 || status[0].ReportedConfigVersion != "reported-1" || status[0].Model != "U7PG2" || status[0].Firmware != "6.8.2" || status[0].IP != "192.0.2.10" || len(status[0].IPv6) != 1 || status[0].DeviceState != 2 || status[0].InformURL == "" || status[0].LastInform.IsZero() {
				t.Fatal("status does not reflect the received inform and drained queue")
			}
		})
	}
}

func TestReloadPreservesDeviceConfigurationButDropsPendingCommands(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")
	c := openController(t, state)
	if err := c.Register(testMAC, testKey); err != nil {
		t.Fatal(err)
	}
	command := setparamReply("saved", "led_enabled=false\n", "")
	if err := c.Queue(testMAC, command); err != nil {
		t.Fatal(err)
	}
	reloaded := openController(t, state)
	if err := reloaded.Register(testMAC, testKey); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	var devices []controller.Device
	if err := json.Unmarshal(data, &devices); err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].Key != testKey {
		t.Fatal("registered identity or key was not persisted")
	}
	if devices[0].LastSetParam == nil || devices[0].LastSetParam.ConfigVersion != "saved" || devices[0].LastSetParam.ManagementConfig != "led_enabled=false\n" {
		t.Fatal("configuration was not preserved after reload and registration")
	}
	server := httptest.NewServer(reloaded)
	defer server.Close()
	if result := exchange(t, server.URL, testKey, true, http.StatusOK); result.Type != "noop" {
		t.Fatal("pending command survived restart")
	}
}

func TestWrongKeyDoesNotConsumeCommand(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")
	c := openController(t, state)
	if err := c.Register(testMAC, testKey); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(c)
	defer server.Close()
	exchange(t, server.URL, testKey, true, http.StatusOK)
	if err := c.Queue(testMAC, setparamReply("waiting", "cfgversion=waiting\n", "")); err != nil {
		t.Fatal(err)
	}
	before := c.Status()
	exchange(t, server.URL, "ffffffffffffffffffffffffffffffff", true, http.StatusBadRequest)
	plain := []byte(`{"cfgversion":"forged","model":"forged","type":"uap","radio_table":[{"name":"wifi0","radio":"ng"}]}`)
	plaintext := make([]byte, 40)
	copy(plaintext, "TNBU")
	binary.BigEndian.PutUint32(plaintext[4:8], 1)
	copy(plaintext[8:14], []byte{2, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint32(plaintext[32:36], 1)
	binary.BigEndian.PutUint32(plaintext[36:40], uint32(len(plain)))
	plaintext = append(plaintext, plain...)
	oversized := append(bytes.Repeat([]byte(" "), 8*1024*1024+1), plain...)
	packet := inform.Packet{MAC: [6]byte{2, 0, 0, 0, 0, 1}, Payload: oversized}
	zlibBody, err := packet.Encode(testKey)
	if err != nil {
		t.Fatal(err)
	}
	snappyBody := requestGCM(t, snappy.Encode(nil, oversized), 4, 1)
	for _, body := range [][]byte{zlibBody, snappyBody} {
		decoded, err := inform.Decode(body, testKey)
		if err != nil || len(decoded.Payload) <= 8*1024*1024 {
			t.Fatal("unbounded decoder did not yield the oversized report")
		}
		var report informmodel.Report
		if err := json.Unmarshal(decoded.Payload, &report); err != nil || report.ConfigVersion != "forged" || len(report.RadioTable) != 1 {
			t.Fatal("oversized request is not a valid report eligible for observation updates")
		}
	}
	for _, body := range [][]byte{plaintext, zlibBody, snappyBody} {
		response, err := http.Post(server.URL+"/inform", "application/x-binary", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusBadRequest || !reflect.DeepEqual(c.Status(), before) {
			t.Errorf("rejected inform changed observations or the queued command: HTTP %d, pending %d", response.StatusCode, c.Status()[0].Pending)
		}
	}
	if result := exchange(t, server.URL, testKey, true, http.StatusOK); result.ConfigVersion != "waiting" {
		t.Fatal("invalid inform consumed the queued command")
	}
	packet.Payload = plain
	belowLimitZlib, err := packet.Encode(testKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range [][]byte{belowLimitZlib, requestGCM(t, plain, 0, 1), requestGCM(t, snappy.Encode(nil, plain), 4, 1)} {
		response, err := http.Post(server.URL+"/inform", "application/x-binary", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusOK || c.Status()[0].ReportedConfigVersion != "forged" {
			t.Fatal("valid encrypted inform was rejected")
		}
	}
	var compressed bytes.Buffer
	writer := zlib.NewWriter(&compressed)
	if _, err := writer.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Queue(testMAC, setparamReply("physical-version", "cfgversion=physical-version\n", "")); err != nil {
		t.Fatal(err)
	}
	before = c.Status()
	for _, packetVersion := range []uint32{2, 0} {
		body := requestGCM(t, compressed.Bytes(), 2, packetVersion)
		response, err := http.Post(server.URL+"/inform", "application/x-binary", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if packetVersion == 2 {
			if response.StatusCode != http.StatusBadRequest || !reflect.DeepEqual(c.Status(), before) {
				t.Fatal("unsupported packet version changed observations or consumed the command")
			}
		} else if response.StatusCode != http.StatusOK || c.Status()[0].Pending != 0 {
			t.Fatal("physical packet version 0 was rejected or did not receive the queued command")
		}
	}
	persisted, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	var devices []controller.Device
	if err := json.Unmarshal(persisted, &devices); err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].Descriptor == nil || devices[0].Descriptor.Protocol.PacketVersion != 0 || devices[0].Descriptor.Protocol.PayloadVersion != 1 || !devices[0].Descriptor.Protocol.SystemConfig || !devices[0].Descriptor.Protocol.ManagementConfig {
		t.Fatal("physical packet version 0 did not establish verified configuration support")
	}
}

func requestGCM(t *testing.T, payload []byte, compression uint16, packetVersion uint32) []byte {
	t.Helper()
	key, err := inform.ParseKey(testKey)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 40)
	copy(header, "TNBU")
	binary.BigEndian.PutUint32(header[4:8], packetVersion)
	copy(header[8:14], []byte{2, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(header[14:16], 1|8|compression)
	binary.BigEndian.PutUint32(header[32:36], 1)
	binary.BigEndian.PutUint32(header[36:40], uint32(len(payload)+gcm.Overhead()))
	return append(header, gcm.Seal(nil, header[16:32], payload, header)...)
}

func TestControlImportsKeyAndQueuesInformReply(t *testing.T) {
	directory := t.TempDir()
	keyFile := filepath.Join(directory, "inform-key")
	if err := os.WriteFile(keyFile, []byte(testKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := openController(t, filepath.Join(directory, "state.json"))
	control := httptest.NewServer(http.HandlerFunc(c.Control))
	defer control.Close()
	command := setparamReply("control-1", "cfgversion=control-1\n", "")
	requests := []controller.ControlRequest{
		{Operation: "import", MAC: testMAC, KeyFile: keyFile},
		{Operation: "send", MAC: testMAC, Command: &command},
	}
	for _, request := range requests {
		body, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.Post(control.URL, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("%s status = %d", request.Operation, response.StatusCode)
		}
	}
	server := httptest.NewServer(c)
	defer server.Close()
	if result := exchange(t, server.URL, testKey, true, http.StatusOK); result.ConfigVersion != "control-1" {
		t.Fatal("control API command did not reach the AP")
	}
}

func TestAdoptQueuesCapturedConfigWithGeneratedSSHCredentials(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")
	c := openController(t, state)
	if err := c.Register(testMAC, testKey); err != nil {
		t.Fatal(err)
	}
	template := setparamReply("old", "authkey=old\ninform_url=http://old/inform\ncfgversion=old\n", "users.status=enabled\nusers.1.name=old\nusers.1.password=old\nsshd.status=enabled\nsshd.1.status=enabled\nsshd.auth.passwd=enabled\nwireless.1.ssid=keep-me\n")
	if err := c.Adopt(testMAC, template, true); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	var devices []controller.Device
	if err := json.Unmarshal(data, &devices); err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].SSHUsername != "unifi-go" || devices[0].SSHPassword == "" {
		t.Fatal("generated SSH credentials were not persisted")
	}
	if err := sha512_crypt.New().Verify(devices[0].SSHPasswordHash, []byte(devices[0].SSHPassword)); err != nil {
		t.Fatal("persisted SSH password does not match its device hash")
	}
	server := httptest.NewServer(c)
	defer server.Close()
	reply := exchange(t, server.URL, testKey, true, http.StatusOK)
	if !strings.Contains(reply.Management, "authkey="+testKey+"\n") || !strings.Contains(reply.Management, "inform_url="+testURL+"\n") {
		t.Fatal("adoption reply did not retain the inform key and URL")
	}
	if !strings.Contains(reply.System, "users.1.name=unifi-go\n") || !strings.Contains(reply.System, "users.1.password="+devices[0].SSHPasswordHash+"\n") {
		t.Fatal("adoption reply did not provision generated SSH credentials")
	}
	if !strings.Contains(reply.System, "wireless.1.ssid=keep-me\n") {
		t.Fatal("adoption reply did not preserve captured configuration")
	}
}

func TestAdoptUsesInformKeyTransitionWithoutSSH(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")
	c := openController(t, state)
	template := setparamReply("old", "authkey=old\ninform_url=http://old/inform\ncfgversion=old\n", "users.status=enabled\nusers.1.name=old\nusers.1.password=old\nsshd.status=enabled\nsshd.1.status=enabled\nsshd.auth.passwd=enabled\n")
	if err := c.Adopt(testMAC, template, false); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	var devices []controller.Device
	if err := json.Unmarshal(data, &devices); err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].Key != inform.DefaultKey || devices[0].NextKey == "" {
		t.Fatal("adoption did not persist the default and assigned keys")
	}
	server := httptest.NewServer(c)
	defer server.Close()
	transition := exchange(t, server.URL, inform.DefaultKey, false, http.StatusOK)
	if transition.Command != "set-adopt" || transition.Key != devices[0].NextKey || transition.URI != testURL {
		t.Fatal("default-key inform did not receive the key transition")
	}
	provision := exchange(t, server.URL, devices[0].NextKey, true, http.StatusOK)
	if provision.Type != "setparam" || !strings.Contains(provision.Management, "authkey="+devices[0].NextKey+"\n") {
		t.Fatal("assigned-key inform did not receive provisioning")
	}
	data, err = os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	devices = nil
	if err := json.Unmarshal(data, &devices); err != nil {
		t.Fatal(err)
	}
	if devices[0].Key != transition.Key || devices[0].NextKey != "" {
		t.Fatal("assigned key was not committed after the device used it")
	}
}
