// Package fixture creates public protocol fixtures from private packet captures.
package fixture

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/jamesbraid/unifi-emu/inform"

	"goodkind.io/unifi-go/internal/configmap"
	"goodkind.io/unifi-go/internal/informmodel"
)

var (
	fixtureMarker      = strings.Join([]string{"fixture", "marker"}, "-")
	syntheticPacketKey = strings.Repeat("0", 32)
)

var (
	macPattern        = regexp.MustCompile(`(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}|(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}`)
	ipv4Pattern       = regexp.MustCompile(`(?:[0-9]+\.){3}[0-9]+`)
	ipv6Pattern       = regexp.MustCompile(`(?i)(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}`)
	jsonStringPattern = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
)

// Options selects fixture inputs and output.
type Options struct {
	Capture        string
	Family         string
	Output         string
	KeyFile        string
	ProvenanceFile string
}

type frame struct {
	Number int
	Stream int
	Body   []byte
}

// Descriptor records safe fixture provenance.
type Descriptor struct {
	Family                string          `json:"family"`
	ControllerVersion     string          `json:"controller_version"`
	ControllerImageDigest string          `json:"controller_image_digest"`
	Emitters              []PublicEmitter `json:"emitters"`
	Source                string          `json:"source"`
	SanitizationScheme    string          `json:"sanitization_scheme"`
}

// RunProvenance is verified metadata supplied independently from packet content.
type RunProvenance struct {
	ControllerVersion     string          `json:"controller_version"`
	ControllerImageDigest string          `json:"controller_image_digest"`
	Source                string          `json:"source"`
	Emitters              []SourceEmitter `json:"emitters"`
}

// SourceEmitter is private verified metadata keyed by the packet-header MAC.
type SourceEmitter struct {
	MAC                 string `json:"mac"`
	Model               string `json:"model"`
	EmulatorRevision    string `json:"emulator_revision"`
	EmitterPatch        string `json:"emitter_patch,omitempty"`
	EmitterImageDigest  string `json:"emitter_image_digest"`
	CapabilityRationale string `json:"capability_rationale"`
}

// PublicEmitter records provenance under a synthetic device identity.
type PublicEmitter struct {
	Device              string `json:"device"`
	Model               string `json:"model"`
	EmulatorRevision    string `json:"emulator_revision"`
	EmitterPatch        string `json:"emitter_patch,omitempty"`
	EmitterImageDigest  string `json:"emitter_image_digest"`
	CapabilityRationale string `json:"capability_rationale"`
}

// Provenance identifies the source exchange.
type Provenance struct {
	FrameNumber int    `json:"frame_number"`
	TCPStream   int    `json:"tcp_stream"`
	Model       string `json:"emulated_model"`
	Device      string `json:"device"`
}

// Operation contains one sanitized configuration exchange.
type Operation struct {
	Provenance Provenance       `json:"provenance"`
	Reply      wireReply        `json:"reply"`
	Management configmap.Values `json:"management"`
	System     configmap.Values `json:"system"`
}

type wireReply struct {
	Type             string `json:"_type"`
	ConfigVersion    string `json:"cfgversion"`
	ManagementConfig string `json:"mgmt_cfg,omitempty"`
	SystemConfig     string `json:"system_cfg,omitempty"`
}

type exchange struct {
	Before    Operation          `json:"before"`
	Reply     Operation          `json:"reply"`
	Report    informmodel.Report `json:"report"`
	PacketMAC [6]byte            `json:"packet_mac"`
	Emitter   PublicEmitter      `json:"emitter"`
}

type decodedFixture struct {
	Exchanges       []exchange
	SensitiveValues map[string]string
}

type deviceState struct {
	ID            string
	Family        string
	Model         string
	LastOperation *Operation
	Pending       *Operation
	PacketMAC     [6]byte
	Emitter       SourceEmitter
}

// ConfigDiff describes additions, changes, and removals without ambiguity.
type ConfigDiff struct {
	Added   configmap.Values `json:"added"`
	Changed configmap.Values `json:"changed"`
	Removed []string         `json:"removed"`
}

func readProvenance(path string) (RunProvenance, error) {
	if path == "" {
		return RunProvenance{}, fmt.Errorf("provenance is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		slog.Warn("fixture provenance read failed")
		return RunProvenance{}, fmt.Errorf("read provenance: %w", err)
	}
	var provenance RunProvenance
	if err := json.Unmarshal(data, &provenance); err != nil {
		slog.Warn("fixture provenance decode failed")
		return RunProvenance{}, fmt.Errorf("decode provenance: %w", err)
	}
	if provenance.ControllerVersion == "" || provenance.ControllerImageDigest == "" || provenance.Source == "" || len(provenance.Emitters) == 0 {
		return RunProvenance{}, fmt.Errorf("provenance is incomplete")
	}
	for _, emitter := range provenance.Emitters {
		if !isMAC(emitter.MAC) || emitter.Model == "" || emitter.EmulatorRevision == "" || emitter.EmitterImageDigest == "" || emitter.CapabilityRationale == "" {
			return RunProvenance{}, fmt.Errorf("emitter provenance is incomplete")
		}
	}
	return provenance, nil
}

// Generate writes sanitized fixtures from captured traffic.
func Generate(options Options) error {
	if options.Family != "ap" && options.Family != "switch" {
		return fmt.Errorf("family must be ap or switch")
	}
	if options.Capture == "" || options.Output == "" {
		return fmt.Errorf("capture and output are required")
	}
	provenance, err := readProvenance(options.ProvenanceFile)
	if err != nil {
		return err
	}
	frames, err := readHTTPFrames(options.Capture)
	if err != nil {
		return err
	}
	keys, err := readKeys(options.KeyFile)
	if err != nil {
		return err
	}
	decoded, err := unmarshalFrames(frames, keys, options.Family, provenance)
	if err != nil {
		return err
	}
	if len(decoded.Exchanges) < 2 {
		return fmt.Errorf("capture contains no %s report and setparam pair", options.Family)
	}
	if err := writeFixture(options, provenance, decoded); err != nil {
		return err
	}
	slog.Info("generated fixtures", "family", options.Family, "exchanges", len(decoded.Exchanges))
	return nil
}

func readHTTPFrames(capture string) ([]frame, error) {
	slog.Debug("reading captured HTTP frames")
	command := exec.CommandContext(context.Background(), "tshark", "-r", capture, "-Y", "http.file_data", "-T", "fields", "-E", "separator=\t", "-e", "frame.number", "-e", "tcp.stream", "-e", "http.file_data")
	output, err := command.Output()
	if err != nil {
		slog.Warn("fixture tshark extraction failed")
		return nil, fmt.Errorf("extract HTTP bodies with tshark: %w", err)
	}
	var frames []frame
	for line := range strings.SplitSeq(strings.TrimSpace(string(output)), "\n") {
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) != 3 {
			continue
		}
		var item frame
		if _, err := fmt.Sscanf(parts[0], "%d", &item.Number); err != nil {
			slog.Warn("fixture frame number parse failed")
			return nil, fmt.Errorf("parse frame number: %w", err)
		}
		if _, err := fmt.Sscanf(parts[1], "%d", &item.Stream); err != nil {
			slog.Warn("fixture TCP stream parse failed")
			return nil, fmt.Errorf("parse TCP stream: %w", err)
		}
		item.Body, err = hex.DecodeString(strings.ReplaceAll(parts[2], ":", ""))
		if err != nil {
			slog.Warn("fixture HTTP body decode failed")
			return nil, fmt.Errorf("decode frame %d body: %w", item.Number, err)
		}
		if bytes.HasPrefix(item.Body, []byte("TNBU")) {
			frames = append(frames, item)
		}
	}
	return frames, nil
}

func readKeys(path string) ([]string, error) {
	slog.Debug("reading fixture keys", "provided", path != "")
	keys := []string{inform.DefaultKey}
	if path == "" {
		return keys, nil
	}
	file, err := os.Open(path)
	if err != nil {
		slog.Warn("fixture key file open failed")
		return nil, fmt.Errorf("open key file: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		candidate := strings.TrimSpace(scanner.Text())
		if _, err := hex.DecodeString(candidate); err == nil && len(candidate) == 32 {
			keys = append(keys, candidate)
		}
	}
	if err := scanner.Err(); err != nil {
		slog.Warn("fixture key file read failed")
		return nil, fmt.Errorf("read key file: %w", err)
	}
	return keys, nil
}

func unmarshalFrames(frames []frame, seedKeys []string, family string, provenance RunProvenance) (decodedFixture, error) {
	slog.Debug("decoding captured frames", "family", family, "frames", len(frames))
	decoder := frameDecoder{Family: family, SeedKeys: seedKeys, KeysByMAC: make(map[string][]string), States: make(map[string]*deviceState), Emitters: make(map[string]SourceEmitter), Exchanges: nil, SensitiveValues: make(map[string]string)}
	for _, emitter := range provenance.Emitters {
		decoder.Emitters[strings.ToLower(emitter.MAC)] = emitter
		decoder.addSensitive(emitter.MAC, "emitter.mac")
	}
	for _, item := range frames {
		if len(item.Body) < 40 {
			slog.Warn("short TNBU fixture packet", "frame", item.Number)
			return decodedFixture{}, fmt.Errorf("frame %d has short TNBU body", item.Number)
		}
		mac := net.HardwareAddr(item.Body[8:14]).String()
		state := decoder.stateForMAC(mac)
		if state == nil {
			continue
		}
		candidates := append([]string{}, decoder.KeysByMAC[mac]...)
		candidates = append(candidates, decoder.SeedKeys...)
		packet, err := decodeWithKeys(item.Body, candidates)
		if err != nil {
			continue
		}
		if err := decoder.consumePayload(item, mac, state, packet.Payload); err != nil {
			return decodedFixture{}, err
		}
	}
	return decodedFixture{Exchanges: decoder.Exchanges, SensitiveValues: decoder.SensitiveValues}, nil
}

type frameDecoder struct {
	Family          string
	SeedKeys        []string
	KeysByMAC       map[string][]string
	States          map[string]*deviceState
	Emitters        map[string]SourceEmitter
	Exchanges       []exchange
	SensitiveValues map[string]string
}

func (decoder *frameDecoder) stateForMAC(mac string) *deviceState {
	if state := decoder.States[mac]; state != nil {
		return state
	}
	emitter, found := decoder.Emitters[mac]
	if !found {
		return nil
	}
	state := &deviceState{ID: fmt.Sprintf("device-%d", len(decoder.States)+1), Family: "", Model: "", LastOperation: nil, Pending: nil, PacketMAC: syntheticMAC(len(decoder.States) + 1), Emitter: emitter}
	decoder.States[mac] = state
	return state
}

func (decoder *frameDecoder) consumePayload(item frame, mac string, state *deviceState, payload []byte) error {
	var reply wireReply
	if err := json.Unmarshal(payload, &reply); err != nil {
		slog.Warn("decoded fixture payload is invalid JSON", "frame", item.Number)
		return fmt.Errorf("frame %d JSON reply: %w", item.Number, err)
	}
	if reply.Type == "setparam" {
		return decoder.consumeReply(item, mac, state, reply)
	}
	var report informmodel.Report
	if err := json.Unmarshal(payload, &report); err != nil {
		slog.Warn("decoded fixture report is invalid", "frame", item.Number)
		return fmt.Errorf("frame %d JSON report: %w", item.Number, err)
	}
	var identity struct {
		Hostname string `json:"hostname"`
	}
	if err := json.Unmarshal(payload, &identity); err == nil {
		decoder.addSensitive(identity.Hostname, "report.hostname")
	}
	return decoder.consumeReport(item, state, report)
}

func (decoder *frameDecoder) consumeReply(item frame, mac string, state *deviceState, reply wireReply) error {
	rawManagement, err := parseConfig(reply.ManagementConfig)
	if err != nil {
		slog.Warn("fixture management config parse failed", "frame", item.Number)
		return fmt.Errorf("frame %d management config: %w", item.Number, err)
	}
	rawSystem, err := parseConfig(reply.SystemConfig)
	if err != nil {
		slog.Warn("fixture system config parse failed", "frame", item.Number)
		return fmt.Errorf("frame %d system config: %w", item.Number, err)
	}
	decoder.collectSensitiveConfig(rawManagement)
	decoder.collectSensitiveConfig(rawSystem)
	operation, err := encodeSanitizedOperation(reply, item)
	if err != nil {
		return err
	}
	if state.Family == decoder.Family {
		if state.Pending != nil {
			slog.Warn("fixture device has multiple replies before a report", "frame", item.Number)
			return fmt.Errorf("frame %d has no intervening device report", item.Number)
		}
		operation.Provenance.Model = state.Model
		operation.Provenance.Device = state.ID
		state.Pending = &operation
	}
	if discovered := rawManagement["authkey"]; isKey(discovered) {
		decoder.KeysByMAC[mac] = append(decoder.KeysByMAC[mac], discovered)
	}
	return nil
}

func (decoder *frameDecoder) consumeReport(item frame, state *deviceState, report informmodel.Report) error {
	reportedFamily := familyForReport(report)
	if report.Model == "" || reportedFamily == "" {
		return nil
	}
	state.Family = reportedFamily
	state.Model = report.Model
	if state.Emitter.Model != report.Model {
		slog.Warn("fixture model provenance mismatch", "frame", item.Number)
		return fmt.Errorf("frame %d model disagrees with provenance", item.Number)
	}
	decoder.collectSensitiveReport(report)
	if state.Pending == nil || reportedFamily != decoder.Family {
		return nil
	}
	if state.LastOperation == nil {
		state.LastOperation = state.Pending
		state.Pending = nil
		return nil
	}
	sanitizeReport(&report, state.PacketMAC)
	publicEmitter := PublicEmitter{Device: state.ID, Model: state.Emitter.Model, EmulatorRevision: state.Emitter.EmulatorRevision, EmitterPatch: state.Emitter.EmitterPatch, EmitterImageDigest: state.Emitter.EmitterImageDigest, CapabilityRationale: state.Emitter.CapabilityRationale}
	decoder.Exchanges = append(decoder.Exchanges, exchange{Before: *state.LastOperation, Reply: *state.Pending, Report: report, PacketMAC: state.PacketMAC, Emitter: publicEmitter})
	state.LastOperation = state.Pending
	state.Pending = nil
	return nil
}

func (decoder *frameDecoder) addSensitive(value string, category string) {
	value = strings.TrimSpace(value)
	if category == "report.port.name" && strings.EqualFold(value, "port") {
		return
	}
	if value != "" && value != "0.0.0.0" && value != "::" && value != "::1" {
		decoder.SensitiveValues[value] = category
	}
}

func (decoder *frameDecoder) collectSensitiveConfig(values configmap.Values) {
	for key, value := range values {
		lower := strings.ToLower(key)
		identity := lower == "hostname" || strings.HasSuffix(lower, ".hostname") || lower == "ssid" || strings.HasSuffix(lower, ".ssid") || strings.HasSuffix(lower, ".name") || isIdentifierField(lower, value)
		if identity || isCredentialField(lower, value) || strings.Contains(lower, "hash") || isMAC(value) || net.ParseIP(value) != nil {
			decoder.addSensitive(value, "config."+key)
		}
	}
}

func (decoder *frameDecoder) collectSensitiveReport(report informmodel.Report) {
	decoder.addSensitive(report.MAC, "report.mac")
	decoder.addSensitive(report.IP, "report.ip")
	decoder.addSensitive(report.LastError, "report.last_error")
	if report.Uplink != nil {
		decoder.addSensitive(report.Uplink.Name, "report.uplink.name")
		decoder.addSensitive(report.Uplink.MAC, "report.uplink.mac")
		decoder.addSensitive(report.Uplink.IP, "report.uplink.ip")
	}
	for _, vap := range report.VAPTable {
		decoder.addSensitive(vap.ESSID, "report.vap.essid")
		decoder.addSensitive(vap.BSSID, "report.vap.bssid")
		for _, station := range vap.Stations {
			decoder.addSensitive(station.MAC, "report.station.mac")
			decoder.addSensitive(station.IP, "report.station.ip")
			decoder.addSensitive(station.Hostname, "report.station.hostname")
		}
	}
	for _, port := range report.PortTable {
		if port.Name != port.Interface {
			decoder.addSensitive(port.Name, "report.port.name")
		}
	}
	for _, ethernet := range report.EthernetTable.Entries {
		decoder.addSensitive(ethernet.MAC, "report.ethernet.mac")
	}
}

func syntheticMAC(index int) [6]byte {
	digest := sha256.Sum256(fmt.Appendf(nil, "fixture-device-%d", index))
	return [6]byte{0x02, 0, 0, 0, 0x10, digest[0]}
}

func sanitizeReport(report *informmodel.Report, deviceMAC [6]byte) {
	report.MAC = net.HardwareAddr(deviceMAC[:]).String()
	report.IP = "203.0.113.200"
	report.ConfigVersion = "fixture-cfg"
	report.LastError = ""
	if report.Uplink != nil {
		report.Uplink.Name = "fixture-uplink"
		report.Uplink.MAC = "02:00:00:00:00:11"
		report.Uplink.IP = "203.0.113.1"
	}
	for vapIndex := range report.VAPTable {
		report.VAPTable[vapIndex].ESSID = "fixture-wifi"
		report.VAPTable[vapIndex].BSSID = fmt.Sprintf("02:00:00:00:01:%02x", vapIndex)
		for stationIndex := range report.VAPTable[vapIndex].Stations {
			station := &report.VAPTable[vapIndex].Stations[stationIndex]
			station.MAC = fmt.Sprintf("02:00:00:00:02:%02x", stationIndex)
			station.IP = fmt.Sprintf("203.0.113.%d", 100+stationIndex)
			station.Hostname = fmt.Sprintf("fixture-client-%d", stationIndex+1)
		}
	}
	for portIndex := range report.PortTable {
		report.PortTable[portIndex].Name = fmt.Sprintf("fixture-interface-%d", portIndex+1)
	}
	for ethernetIndex := range report.EthernetTable.Entries {
		report.EthernetTable.Entries[ethernetIndex].MAC = fmt.Sprintf("02:00:00:00:03:%02x", ethernetIndex)
	}
}

func decodeWithKeys(body []byte, keys []string) (*inform.Packet, error) {
	for _, key := range keys {
		packet, err := inform.Decode(body, key)
		if err == nil {
			return packet, nil
		}
	}
	return nil, fmt.Errorf("no usable key")
}

func familyForReport(report informmodel.Report) string {
	if len(report.RadioTable) != 0 {
		return "ap"
	}
	if len(report.PortTable) != 0 {
		return "switch"
	}
	return ""
}

func encodeSanitizedOperation(reply wireReply, source frame) (Operation, error) {
	slog.Debug("sanitizing captured operation", "frame", source.Number)
	management, err := sanitizeConfig(reply.ManagementConfig)
	if err != nil {
		slog.Warn("fixture management sanitization failed", "frame", source.Number)
		return Operation{}, fmt.Errorf("frame %d management config: %w", source.Number, err)
	}
	system, err := sanitizeConfig(reply.SystemConfig)
	if err != nil {
		slog.Warn("fixture system sanitization failed", "frame", source.Number)
		return Operation{}, fmt.Errorf("frame %d system config: %w", source.Number, err)
	}
	safeReply := wireReply{Type: "setparam", ConfigVersion: "fixture-cfg", ManagementConfig: "", SystemConfig: ""}
	provenance := Provenance{FrameNumber: source.Number, TCPStream: source.Stream, Model: "", Device: ""}
	return Operation{Provenance: provenance, Reply: safeReply, Management: management, System: system}, nil
}

func sanitizeConfig(encoded string) (configmap.Values, error) {
	values, err := parseConfig(encoded)
	if err != nil {
		return nil, err
	}
	for key, value := range values {
		lower := strings.ToLower(key)
		switch {
		case isCredentialField(lower, value):
			values[key] = fixtureMarker
		case lower == "ssid", strings.HasSuffix(lower, ".ssid"):
			values[key] = "fixture-wifi"
		case lower == "hostname", strings.HasSuffix(lower, ".hostname"), strings.HasSuffix(lower, ".name"):
			values[key] = "fixture-name"
		case strings.HasSuffix(lower, ".server"):
			values[key] = "fixture-server.example"
		case isIdentifierField(lower, value):
			values[key] = syntheticIdentifier(value)
		case value == "0.0.0.0" || value == "::" || value == "::1":
			continue
		case net.ParseIP(value) != nil:
			if strings.Contains(value, ":") {
				values[key] = "2001:db8::200"
			} else {
				values[key] = "203.0.113.200"
			}
		case isMAC(value):
			values[key] = "02:00:00:00:00:10"
		case strings.Contains(lower, "secret"), strings.Contains(lower, "token"), strings.Contains(lower, "private"), strings.Contains(lower, "hash"):
			return nil, fmt.Errorf("unclassified sensitive configuration key %q", key)
		default:
			value = macPattern.ReplaceAllString(value, "02:00:00:00:00:10")
			value = ipv4Pattern.ReplaceAllString(value, "203.0.113.200")
			values[key] = replaceEmbeddedIPv6(value)
		}
	}
	if err := validateSafeConfig(values); err != nil {
		return nil, err
	}
	return values, nil
}

func isIdentifierField(lower string, value string) bool {
	return strings.Contains(lower, "uuid") || strings.Contains(lower, "siteid") || strings.Contains(lower, "site_id") || strings.Contains(lower, "reporterid") || strings.Contains(lower, "reporter_id") || strings.Contains(lower, "anonymous_controller_id") || strings.HasSuffix(lower, ".id") && len(value) >= 20
}

func syntheticIdentifier(value string) string {
	digest := sha256.Sum256([]byte("fixture-id:" + value))
	hexValue := hex.EncodeToString(digest[:16])
	return fmt.Sprintf("%s-%s-4%s-8%s-%s", hexValue[:8], hexValue[8:12], hexValue[13:16], hexValue[17:20], hexValue[20:32])
}

func replaceEmbeddedIPv6(value string) string {
	return ipv6Pattern.ReplaceAllStringFunc(value, func(candidate string) string {
		address, err := netip.ParseAddr(candidate)
		if err != nil || !address.Is6() || address.IsUnspecified() || address.IsLoopback() {
			return candidate
		}
		return "2001:db8::200"
	})
}

func isCredentialField(lower string, value string) bool {
	if lower == "sshd.auth.passwd" && value == "enabled" {
		return false
	}
	return strings.Contains(lower, "password") || strings.Contains(lower, "passwd") || strings.Contains(lower, "psk") || strings.HasSuffix(lower, ".key") || strings.HasSuffix(lower, "_key") || lower == "authkey"
}

func validateSafeConfig(values configmap.Values) error {
	for key, value := range values {
		for _, candidate := range ipv4Pattern.FindAllString(value, -1) {
			if candidate != "0.0.0.0" && candidate != "203.0.113.200" {
				return fmt.Errorf("configuration key %q retains a source IPv4 address", key)
			}
		}
		for _, candidate := range macPattern.FindAllString(value, -1) {
			if candidate != "02:00:00:00:00:10" {
				return fmt.Errorf("configuration key %q retains a source MAC address", key)
			}
		}
	}
	return nil
}

func parseConfig(encoded string) (configmap.Values, error) {
	slog.Debug("parsing captured configuration")
	var records []string
	for record := range strings.SplitSeq(encoded, "\n") {
		trimmed := strings.TrimSpace(record)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		records = append(records, record)
	}
	if len(records) == 0 {
		return configmap.Values{}, nil
	}
	values, err := configmap.Parse(strings.Join(records, "\n") + "\n")
	if err != nil {
		slog.Warn("fixture config parse failed")
		return nil, fmt.Errorf("parse configuration records: %w", err)
	}
	return values, nil
}

func writeFixture(options Options, provenance RunProvenance, decoded decodedFixture) error {
	slog.Debug("writing fixture files", "family", options.Family)
	exchanges := decoded.Exchanges
	if err := os.MkdirAll(options.Output, 0o755); err != nil {
		slog.Warn("fixture output creation failed")
		return fmt.Errorf("create output directory: %w", err)
	}
	if err := removeGeneratedFiles(options.Output); err != nil {
		return err
	}
	var emitters []PublicEmitter
	seenDevices := make(map[string]bool)
	for _, item := range exchanges {
		if !seenDevices[item.Emitter.Device] {
			emitters = append(emitters, item.Emitter)
			seenDevices[item.Emitter.Device] = true
		}
	}
	descriptor := Descriptor{Family: options.Family, ControllerVersion: provenance.ControllerVersion, ControllerImageDigest: provenance.ControllerImageDigest, Emitters: emitters, Source: provenance.Source, SanitizationScheme: "documentation identities and synthetic AES key"}
	if err := validatePublication(descriptor, exchanges, decoded.SensitiveValues); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(options.Output, "descriptor.json"), descriptor); err != nil {
		return err
	}
	baseline := exchanges[0].Before
	if err := writeJSON(filepath.Join(options.Output, "baseline-setparam.json"), baseline); err != nil {
		return err
	}
	if err := writePacket(filepath.Join(options.Output, "baseline-setparam.bin"), baseline, exchanges[0].PacketMAC); err != nil {
		return err
	}
	for index, item := range exchanges {
		prefix := filepath.Join(options.Output, fmt.Sprintf("operation-%02d", index+1))
		if err := writeJSON(prefix+"-before.json", item.Before); err != nil {
			return err
		}
		if err := writeJSON(prefix+"-reply.json", item.Reply); err != nil {
			return err
		}
		if err := writePacket(prefix+"-reply.bin", item.Reply, item.PacketMAC); err != nil {
			return err
		}
		if err := writeJSON(prefix+"-report.json", item.Report); err != nil {
			return err
		}
		if err := writeJSON(prefix+"-expected-diff.json", configDiff(item.Before.System, item.Reply.System)); err != nil {
			return err
		}
	}
	return nil
}

func validatePublication(descriptor Descriptor, exchanges []exchange, sensitiveValues map[string]string) error {
	data, err := marshalValidation(descriptor)
	if err != nil {
		slog.Warn("fixture validation marshal failed")
		return fmt.Errorf("marshal fixture validation input: %w", err)
	}
	var aggregate bytes.Buffer
	aggregate.Write(data)
	for _, item := range exchanges {
		for _, operation := range []Operation{item.Before, item.Reply} {
			operationData, marshalErr := marshalValidation(operation)
			if marshalErr != nil {
				slog.Warn("fixture operation validation marshal failed")
				return fmt.Errorf("marshal operation validation input: %w", marshalErr)
			}
			aggregate.Write(operationData)
		}
		reportData, marshalErr := marshalValidation(item.Report)
		if marshalErr != nil {
			slog.Warn("fixture report validation marshal failed")
			return fmt.Errorf("marshal report validation input: %w", marshalErr)
		}
		aggregate.Write(reportData)
	}
	leaves, err := decodedStringLeaves(aggregate.Bytes())
	if err != nil {
		return fmt.Errorf("decode fixture validation strings: %w", err)
	}
	for value, category := range sensitiveValues {
		if trackedValueRemains(leaves, value, category) {
			path := publicationValuePath(descriptor, exchanges, value, category)
			return fmt.Errorf("sanitized output retains tracked source category %s length %d in %s", category, len(value), path)
		}
	}
	for _, leaf := range leaves {
		if err := validatePublishedAddresses(leaf); err != nil {
			return err
		}
	}
	return nil
}

func validatePublishedAddresses(value string) error {
	for _, candidate := range macPattern.FindAllString(value, -1) {
		address, err := net.ParseMAC(candidate)
		if err != nil {
			continue
		}
		canonical := address.String()
		if !strings.HasPrefix(canonical, "02:00:00:00:") && canonical != "00:00:00:00:00:00" && canonical != "ff:ff:ff:ff:ff:ff" {
			return fmt.Errorf("sanitized output retains a non-synthetic MAC address")
		}
	}
	for _, candidate := range ipv4Pattern.FindAllString(value, -1) {
		address, err := netip.ParseAddr(candidate)
		if err != nil || address.IsUnspecified() {
			continue
		}
		if !netip.MustParsePrefix("192.0.2.0/24").Contains(address) && !netip.MustParsePrefix("198.51.100.0/24").Contains(address) && !netip.MustParsePrefix("203.0.113.0/24").Contains(address) {
			return fmt.Errorf("sanitized output retains a non-documentation IPv4 address")
		}
	}
	for _, candidate := range ipv6Pattern.FindAllString(value, -1) {
		address, err := netip.ParseAddr(candidate)
		if err != nil || !address.Is6() || address.IsUnspecified() || address.IsLoopback() {
			continue
		}
		if !netip.MustParsePrefix("2001:db8::/32").Contains(address) {
			return fmt.Errorf("sanitized output retains a non-documentation IPv6 address")
		}
	}
	return nil
}

func marshalValidation[T Descriptor | Operation | informmodel.Report](value T) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		slog.Warn("fixture validation value marshal failed")
		return nil, fmt.Errorf("marshal validation value: %w", err)
	}
	return data, nil
}

func decodedStringLeaves(data []byte) ([]string, error) {
	var leaves []string
	for _, location := range jsonStringPattern.FindAllIndex(data, -1) {
		decoded, err := strconv.Unquote(string(data[location[0]:location[1]]))
		if err != nil {
			slog.Warn("fixture JSON leaf unquote failed")
			return nil, fmt.Errorf("unquote JSON string leaf: %w", err)
		}
		leaves = append(leaves, strings.ToLower(decoded))
	}
	return leaves, nil
}

func trackedValueRemains(leaves []string, value string, category string) bool {
	lowerValue := strings.ToLower(value)
	strongCategory := strings.Contains(category, "credential") || strings.Contains(category, "key") || strings.Contains(category, "hash") || strings.Contains(category, "ssid") || strings.Contains(category, ".mac") || strings.Contains(category, ".ip")
	boundary := regexp.MustCompile(`(^|[^a-z0-9_-])` + regexp.QuoteMeta(lowerValue) + `([^a-z0-9_-]|$)`)
	for _, leaf := range leaves {
		if strongCategory && strings.Contains(leaf, lowerValue) {
			return true
		}
		if !strongCategory && boundary.FindStringIndex(leaf) != nil {
			return true
		}
	}
	return false
}

func publicationValuePath(descriptor Descriptor, exchanges []exchange, value string, category string) string {
	needle := strings.ToLower(value)
	if strings.Contains(strings.ToLower(fmt.Sprintf("%v", descriptor)), needle) {
		return "descriptor"
	}
	for index, item := range exchanges {
		for key, fieldValue := range item.Before.Management {
			if trackedValueRemains([]string{strings.ToLower(fieldValue)}, value, category) {
				return fmt.Sprintf("operation-%02d-before.management.%s", index+1, key)
			}
		}
		for key, fieldValue := range item.Before.System {
			if trackedValueRemains([]string{strings.ToLower(fieldValue)}, value, category) {
				return fmt.Sprintf("operation-%02d-before.system.%s", index+1, key)
			}
		}
		if strings.Contains(strings.ToLower(fmt.Sprintf("%v", item.Before)), needle) {
			return fmt.Sprintf("operation-%02d-before", index+1)
		}
		if strings.Contains(strings.ToLower(fmt.Sprintf("%v", item.Reply)), needle) {
			return fmt.Sprintf("operation-%02d-reply", index+1)
		}
		if strings.Contains(strings.ToLower(fmt.Sprintf("%v", item.Report)), needle) {
			return fmt.Sprintf("operation-%02d-report", index+1)
		}
	}
	return "encoded-plaintext"
}

func removeGeneratedFiles(output string) error {
	entries, err := os.ReadDir(output)
	if err != nil {
		slog.Warn("fixture output read failed")
		return fmt.Errorf("read fixture output: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		generated := name == "descriptor.json" || strings.HasPrefix(name, "baseline-setparam.") || strings.HasPrefix(name, "operation-")
		if generated && !entry.IsDir() {
			if err := os.Remove(filepath.Join(output, name)); err != nil {
				slog.Warn("stale fixture removal failed", "name", name)
				return fmt.Errorf("remove stale fixture %q: %w", name, err)
			}
		}
	}
	return nil
}

func writePacket(path string, operation Operation, packetMAC [6]byte) error {
	slog.Debug("writing sanitized packet")
	management, err := operation.Management.Encode()
	if err != nil {
		slog.Warn("fixture management encoding failed")
		return fmt.Errorf("encode management configuration: %w", err)
	}
	system, err := operation.System.Encode()
	if err != nil {
		slog.Warn("fixture system encoding failed")
		return fmt.Errorf("encode system configuration: %w", err)
	}
	payload, err := json.Marshal(wireReply{Type: "setparam", ConfigVersion: "fixture-cfg", ManagementConfig: management, SystemConfig: system})
	if err != nil {
		slog.Warn("fixture reply marshal failed")
		return fmt.Errorf("marshal packet reply: %w", err)
	}
	packet := inform.Packet{MAC: packetMAC, Payload: payload}
	encoded, err := packet.Encode(syntheticPacketKey)
	if err != nil {
		slog.Warn("fixture packet encoding failed")
		return fmt.Errorf("encode inform packet: %w", err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		slog.Warn("fixture packet write failed")
		return fmt.Errorf("write inform packet: %w", err)
	}
	return nil
}

func configDiff(before configmap.Values, after configmap.Values) ConfigDiff {
	diff := ConfigDiff{Added: configmap.Values{}, Changed: configmap.Values{}, Removed: []string{}}
	for key, value := range after {
		beforeValue, exists := before[key]
		if !exists {
			diff.Added[key] = value
		} else if beforeValue != value {
			diff.Changed[key] = value
		}
	}
	for key := range before {
		if _, exists := after[key]; !exists {
			diff.Removed = append(diff.Removed, key)
		}
	}
	slices.Sort(diff.Removed)
	return diff
}

func writeJSON[T Descriptor | Operation | informmodel.Report | configmap.Values | ConfigDiff](path string, value T) error {
	slog.Debug("writing sanitized JSON")
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		slog.Warn("fixture JSON marshal failed")
		return fmt.Errorf("marshal JSON: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		slog.Warn("fixture JSON write failed")
		return fmt.Errorf("write JSON fixture: %w", err)
	}
	return nil
}

func isKey(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 16
}

func isMAC(value string) bool {
	parsed, err := net.ParseMAC(value)
	return err == nil && len(parsed) == 6
}
