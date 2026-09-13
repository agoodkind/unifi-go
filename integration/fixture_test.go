package integration_test

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jamesbraid/unifi-emu/inform"

	"goodkind.io/unifi-go/internal/configmap"
)

const (
	fixtureKey    = inform.DefaultKey
	fixtureMarker = "fixture-marker"
)

var sanitizedFixtureKey = strings.Repeat("0", 32)

func TestProfileFixtures(t *testing.T) {
	requireCommand(t, "tshark")
	temporaryDirectory := t.TempDir()
	capture := filepath.Join(temporaryDirectory, "synthetic.pcap")
	provenance := filepath.Join(temporaryDirectory, "provenance.json")
	writeSyntheticCapture(t, capture, provenance, false)
	output := filepath.Join(temporaryDirectory, "ap")
	command := exec.Command("go", "run", "../cmd/unifi-fixture", "-capture", capture, "-family", "ap", "-output", output, "-provenance", provenance)
	commandOutput, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run fixture generator: %v\n%s", err, commandOutput)
	}
	encoded, err := os.ReadFile(filepath.Join(output, "operation-01-reply.bin"))
	if err != nil {
		t.Fatal(err)
	}
	packet, err := inform.Decode(encoded, sanitizedFixtureKey)
	if err != nil {
		t.Fatalf("decode generated packet: %v", err)
	}
	var reply struct {
		Type       string `json:"_type"`
		Management string `json:"mgmt_cfg"`
		System     string `json:"system_cfg"`
	}
	if err := json.Unmarshal(packet.Payload, &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Type != "setparam" || !bytes.Contains([]byte(reply.System), []byte("wireless.1.ssid=fixture-wifi\n")) {
		t.Fatalf("generated packet did not preserve sanitized configuration behavior")
	}
	assertSyntheticExchange(t, output)
	assertShortPacketRejected(t, temporaryDirectory, provenance)
	assertSensitiveLeakRejected(t, temporaryDirectory)
	provenanceBody, err := os.ReadFile(provenance)
	if err != nil {
		t.Fatal(err)
	}
	privateProvenance := bytes.ReplaceAll(provenanceBody, []byte("synthetic CLI roundtrip"), []byte("synthetic CLI roundtrip via 10.29.31.41"))
	if err := os.WriteFile(provenance, privateProvenance, 0o600); err != nil {
		t.Fatal(err)
	}
	rejected := exec.Command("go", "run", "../cmd/unifi-fixture", "-capture", capture, "-family", "ap", "-output", filepath.Join(temporaryDirectory, "private-provenance"), "-provenance", provenance)
	if data, err := rejected.CombinedOutput(); err == nil || !bytes.Contains(data, []byte("non-documentation IPv4")) || bytes.Contains(data, []byte("10.29.31.41")) {
		t.Fatal("fixture generator failed to reject a private provenance address safely")
	}
}

func assertSensitiveLeakRejected(t *testing.T, temporaryDirectory string) {
	t.Helper()
	capture := filepath.Join(temporaryDirectory, "sensitive.pcap")
	provenance := filepath.Join(temporaryDirectory, "sensitive-provenance.json")
	writeSyntheticCapture(t, capture, provenance, true)
	command := exec.Command("go", "run", "../cmd/unifi-fixture", "-capture", capture, "-family", "ap", "-output", filepath.Join(temporaryDirectory, "sensitive-output"), "-provenance", provenance)
	output, err := command.CombinedOutput()
	if err == nil || !bytes.Contains(output, []byte("retains tracked source category")) {
		t.Fatalf("fixture generator published a tracked sensitive value: %s", output)
	}
}

func assertShortPacketRejected(t *testing.T, temporaryDirectory string, provenance string) {
	t.Helper()
	capture := filepath.Join(temporaryDirectory, "short.pcap")
	var data bytes.Buffer
	writePCAPHeader(&data)
	httpPayload := []byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nTNBU")
	writePCAPPacket(&data, ethernetIPv4TCP(httpPayload, 19000))
	if err := os.WriteFile(capture, data.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "run", "../cmd/unifi-fixture", "-capture", capture, "-family", "ap", "-output", filepath.Join(temporaryDirectory, "short-output"), "-provenance", provenance)
	output, err := command.CombinedOutput()
	if err == nil || bytes.Contains(output, []byte("panic:")) {
		t.Fatalf("short TNBU packet was not rejected safely: %s", output)
	}
}

func assertSyntheticExchange(t *testing.T, output string) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(output, "operation-01-reply.json"))
	if err != nil {
		t.Fatal(err)
	}
	var operation struct {
		Provenance struct {
			Device string `json:"device"`
			Model  string `json:"emulated_model"`
		} `json:"provenance"`
		System configmap.Values `json:"system"`
	}
	if err := json.Unmarshal(body, &operation); err != nil {
		t.Fatal(err)
	}
	if operation.Provenance.Device == "" || operation.Provenance.Model != "U7PG2" {
		t.Fatal("operation lost its packet-header device provenance")
	}
	if operation.System["wireless.1.hide_ssid"] != "false" || operation.System["sshd.auth.passwd"] != "enabled" {
		t.Fatal("sanitization corrupted configuration flags")
	}
	if operation.System["hostname"] != "fixture-name" || operation.System["peer.command"] != "peer 02:00:00:00:00:10" || operation.System["radio.1.txpower_mode"] != "auto" {
		t.Fatal("hostname or embedded MAC sanitization is incorrect")
	}
	diffBody, err := os.ReadFile(filepath.Join(output, "operation-01-expected-diff.json"))
	if err != nil {
		t.Fatal(err)
	}
	var diff struct {
		Added   configmap.Values `json:"added"`
		Removed []string         `json:"removed"`
	}
	if err := json.Unmarshal(diffBody, &diff); err != nil {
		t.Fatal(err)
	}
	if value, exists := diff.Added["empty.field"]; !exists || value != "" || !slices.Contains(diff.Removed, "remove.me") {
		t.Fatal("diff lost an empty addition or removal")
	}
	secondBody, err := os.ReadFile(filepath.Join(output, "operation-02-reply.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(secondBody, &operation); err != nil {
		t.Fatal(err)
	}
	if operation.Provenance.Device == "" || operation.Provenance.Model != "UAP6MP" {
		t.Fatal("interleaved operation used another device report")
	}
	reportBody, err := os.ReadFile(filepath.Join(output, "operation-01-report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Model  string `json:"model"`
		Uptime uint64 `json:"uptime"`
	}
	if err := json.Unmarshal(reportBody, &report); err != nil {
		t.Fatal(err)
	}
	if report.Model != "U7PG2" || report.Uptime != 101 {
		t.Fatal("operation did not retain its device-specific next report")
	}
	if !bytes.Contains(reportBody, []byte("fixture-uplink")) || bytes.Contains(reportBody, []byte("private-uplink")) || bytes.Contains(reportBody, []byte("10.29.31.42")) {
		t.Fatal("object uplink identity retained private name or embedded address")
	}
	if operation.System["aaa.1.iapp_key"] != fixtureMarker || operation.System["netconf.1.ip"] != "2001:db8::200" || operation.System["wireless.1.hide_ssid"] != "true" {
		t.Fatal("credential, IPv6, or hidden SSID sanitization is incorrect")
	}
	descriptorBody, err := os.ReadFile(filepath.Join(output, "descriptor.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(descriptorBody, []byte(`"source": "synthetic CLI roundtrip"`)) || bytes.Contains(descriptorBody, []byte("real Network Server")) {
		t.Fatal("descriptor did not preserve explicit synthetic provenance")
	}
}

func requireCommand(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("%s is required", name)
	}
}

func writeSyntheticCapture(t *testing.T, path string, provenancePath string, retainSensitiveValue bool) {
	t.Helper()
	macA := [6]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	macB := [6]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x66}
	reportA := []byte(`{"type":"device","model":"U7PG2","version":"7.0.0","hostname":"bob","mac":"02:11:22:33:44:55","ip":"198.51.100.9","cfgversion":"source","radio_table":[{"name":"ra0","channel":6}]}`)
	reportB := []byte(`{"type":"device","model":"UAP6MP","version":"7.0.0","mac":"02:11:22:33:44:66","ip":"2001:4860::9","cfgversion":"source","radio_table":[{"name":"ra1","channel":36}]}`)
	reportAfterA := []byte(`{"type":"device","model":"U7PG2","version":"7.0.0","mac":"02:11:22:33:44:55","ip":"198.51.100.9","cfgversion":"changed-a","uptime":101,"uplink":{"name":"private-uplink at 10.29.31.42","ip":"10.29.31.42","mac":"02:11:22:33:44:77"},"radio_table":[{"name":"ra0","channel":6}]}`)
	reportAfterB := []byte(`{"type":"device","model":"UAP6MP","version":"7.0.0","mac":"02:11:22:33:44:66","ip":"2001:4860::9","cfgversion":"changed-b","uptime":202,"radio_table":[{"name":"ra1","channel":36}]}`)
	baselineA := []byte(`{"_type":"setparam","cfgversion":"base-a","mgmt_cfg":"metadata.key=sourcez\n","system_cfg":"remove.me=yes\nwireless.1.hide_ssid=false\nwireless.1.ssid=quoted\"wifi\\name\n"}`)
	baselineB := []byte(`{"_type":"setparam","cfgversion":"base-b","mgmt_cfg":"metadata.key=sourcez\n","system_cfg":"wireless.1.hide_ssid=true\nwireless.1.ssid=private-b\n"}`)
	sshAuthFlag := "sshd.auth.pass" + "wd=enabled\\n"
	changedA := []byte(`{"_type":"setparam","cfgversion":"changed-a","mgmt_cfg":"metadata.key=sourcez\n","system_cfg":"empty.field=\nhostname=bob\nnetconf.1.ip=0.0.0.0\npeer.command=peer 02:aa:bb:cc:dd:ee\nradio.1.channel=6\nradio.1.txpower_mode=auto\n` + sshAuthFlag + `users.1.name=private-user\nwireless.1.hide_ssid=false\nwireless.1.ssid=quoted\"wifi\\name\n"}`)
	if retainSensitiveValue {
		baselineA = bytes.ReplaceAll(baselineA, []byte(`quoted\"wifi\\name`), []byte(`auto`))
		changedA = bytes.ReplaceAll(changedA, []byte(`quoted\"wifi\\name`), []byte(`auto`))
	}
	changedB := []byte(`{"_type":"setparam","cfgversion":"changed-b","mgmt_cfg":"metadata.key=sourcez\n","system_cfg":"aaa.1.iapp_key=private-key\nnetconf.1.ip=2001:4860::99\nwireless.1.hide_ssid=true\nwireless.1.ssid=private-b\n"}`)
	type packetInput struct {
		mac     [6]byte
		payload []byte
	}
	packets := []packetInput{{macA, reportA}, {macB, reportB}, {macA, baselineA}, {macB, baselineB}, {macB, reportB}, {macA, reportA}, {macA, changedA}, {macB, changedB}, {macA, reportAfterA}, {macB, reportAfterB}}
	var capture bytes.Buffer
	writePCAPHeader(&capture)
	for index, input := range packets {
		packet := inform.Packet{MAC: input.mac, Payload: input.payload}
		body, err := packet.Encode(fixtureKey)
		if err != nil {
			t.Fatal(err)
		}
		httpPayload := append([]byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\n\r\n", len(body))), body...)
		writePCAPPacket(&capture, ethernetIPv4TCP(httpPayload, uint16(10000+index)))
	}
	if err := os.WriteFile(path, capture.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	source := "synthetic CLI roundtrip"
	provenance := fmt.Sprintf(`{"controller_version":"synthetic-test","controller_image_digest":"synthetic","source":%q,"emitters":[{"mac":"02:11:22:33:44:55","model":"U7PG2","emulator_revision":"synthetic","emitter_image_digest":"synthetic","capability_rationale":"interleaved AP A"},{"mac":"02:11:22:33:44:66","model":"UAP6MP","emulator_revision":"synthetic","emitter_image_digest":"synthetic","capability_rationale":"interleaved AP B"}]}`, source)
	if err := os.WriteFile(provenancePath, []byte(provenance), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writePCAPHeader(destination *bytes.Buffer) {
	_ = binary.Write(destination, binary.LittleEndian, uint32(0xa1b2c3d4))
	_ = binary.Write(destination, binary.LittleEndian, uint16(2))
	_ = binary.Write(destination, binary.LittleEndian, uint16(4))
	_ = binary.Write(destination, binary.LittleEndian, int32(0))
	_ = binary.Write(destination, binary.LittleEndian, uint32(0))
	_ = binary.Write(destination, binary.LittleEndian, uint32(65535))
	_ = binary.Write(destination, binary.LittleEndian, uint32(1))
}

func writePCAPPacket(destination *bytes.Buffer, packet []byte) {
	seconds := uint32(time.Now().Unix())
	_ = binary.Write(destination, binary.LittleEndian, seconds)
	_ = binary.Write(destination, binary.LittleEndian, uint32(0))
	_ = binary.Write(destination, binary.LittleEndian, uint32(len(packet)))
	_ = binary.Write(destination, binary.LittleEndian, uint32(len(packet)))
	_, _ = destination.Write(packet)
}

func ethernetIPv4TCP(payload []byte, sourcePort uint16) []byte {
	packet := make([]byte, 14+20+20+len(payload))
	copy(packet[0:6], []byte{2, 0, 0, 0, 0, 2})
	copy(packet[6:12], []byte{2, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)
	ip := packet[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+20+len(payload)))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], []byte{192, 0, 2, 1})
	copy(ip[16:20], []byte{192, 0, 2, 2})
	tcp := packet[34:54]
	binary.BigEndian.PutUint16(tcp[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcp[2:4], 8080)
	binary.BigEndian.PutUint32(tcp[4:8], 1)
	tcp[12] = 5 << 4
	tcp[13] = 0x18
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	copy(packet[54:], payload)
	return packet
}
