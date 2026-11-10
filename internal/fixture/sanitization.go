package fixture

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"

	"github.com/jamesbraid/unifi-emu/inform"

	"goodkind.io/unifi-go/internal/configmap"
	"goodkind.io/unifi-go/internal/informmodel"
)

const (
	fixtureSetparamType     = "setparam"
	fixtureIPAddress        = "203.0.113.200"
	fixtureConfigVersion    = "fixture-cfg"
	unspecifiedIPv4Address  = "0.0.0.0"
	firstFixtureStationHost = 100
)

var (
	errNoUsableKey                  = errors.New("no usable key")
	errUnclassifiedConfigurationKey = errors.New("unclassified sensitive configuration key")
	errSourceIPv4Address            = errors.New("retains a source IPv4 address")
	errSourceMACAddress             = errors.New("retains a source MAC address")
)

func syntheticMAC(index int) [6]byte {
	digest := sha256.Sum256(fmt.Appendf(nil, "fixture-device-%d", index))

	return [6]byte{0x02, 0, 0, 0, 0x10, digest[0]}
}

func sanitizeReport(report *informmodel.Report, deviceMAC [6]byte) {
	report.MAC = net.HardwareAddr(deviceMAC[:]).String()
	report.IP = fixtureIPAddress
	report.ConfigVersion = fixtureConfigVersion
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
			station.IP = fmt.Sprintf("203.0.113.%d", firstFixtureStationHost+stationIndex)
			station.Hostname = fmt.Sprintf("fixture-client-%d", stationIndex+1)
		}
	}

	for portIndex := range report.PortTable {
		report.PortTable[portIndex].Name = fmt.Sprintf("fixture-interface-%d", portIndex+1)
	}

	for ethernetIndex := range report.EthernetTable.Entries {
		report.EthernetTable.Entries[ethernetIndex].MAC = fmt.Sprintf(
			"02:00:00:00:03:%02x",
			ethernetIndex,
		)
	}
}

func decodeWithKeys(body []byte, keys []string) (*inform.Packet, error) {
	for _, key := range keys {
		packet, err := inform.Decode(body, key)
		if err == nil {
			return packet, nil
		}
	}

	return nil, errNoUsableKey
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

	safeReply := wireReply{
		Type:             fixtureSetparamType,
		ConfigVersion:    fixtureConfigVersion,
		ManagementConfig: "",
		SystemConfig:     "",
	}
	provenance := Provenance{
		FrameNumber: source.Number,
		TCPStream:   source.Stream,
		Model:       "",
		Device:      "",
	}

	return Operation{
		Provenance: provenance,
		Reply:      safeReply,
		Management: management,
		System:     system,
	}, nil
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
		case lower == "hostname",
			strings.HasSuffix(lower, ".hostname"),
			strings.HasSuffix(lower, ".name"):
			values[key] = "fixture-name"
		case strings.HasSuffix(lower, ".server"):
			values[key] = "fixture-server.example"
		case isIdentifierField(lower, value):
			values[key] = syntheticIdentifier(value)
		case value == unspecifiedIPv4Address || value == "::" || value == "::1":
			continue
		case net.ParseIP(value) != nil:
			if strings.Contains(value, ":") {
				values[key] = "2001:db8::200"
			} else {
				values[key] = fixtureIPAddress
			}
		case isMAC(value):
			values[key] = "02:00:00:00:00:10"
		case strings.Contains(lower, "secret"),
			strings.Contains(lower, "token"),
			strings.Contains(lower, "private"),
			strings.Contains(lower, "hash"):
			slog.Warn("configuration sanitization failed", "err", errUnclassifiedConfigurationKey)

			return nil, fmt.Errorf("%w %q", errUnclassifiedConfigurationKey, key)
		default:
			value = macPattern.ReplaceAllString(value, "02:00:00:00:00:10")
			value = ipv4Pattern.ReplaceAllString(value, fixtureIPAddress)
			values[key] = replaceEmbeddedIPv6(value)
		}
	}

	if err := validateSafeConfig(values); err != nil {
		return nil, err
	}

	return values, nil
}

func isIdentifierField(lower string, value string) bool {
	return strings.Contains(lower, "uuid") || strings.Contains(lower, "siteid") ||
		strings.Contains(lower, "site_id") ||
		strings.Contains(lower, "reporterid") ||
		strings.Contains(lower, "reporter_id") ||
		strings.Contains(lower, "anonymous_controller_id") ||
		strings.HasSuffix(lower, ".id") && len(value) >= 20
}

func syntheticIdentifier(value string) string {
	digest := sha256.Sum256([]byte("fixture-id:" + value))
	hexValue := hex.EncodeToString(digest[:16])

	return fmt.Sprintf(
		"%s-%s-4%s-8%s-%s",
		hexValue[:8],
		hexValue[8:12],
		hexValue[13:16],
		hexValue[17:20],
		hexValue[20:32],
	)
}

func replaceEmbeddedIPv6(value string) string {
	return ipv6Pattern.ReplaceAllStringFunc(
		value,
		func(candidate string) string {
			address, err := netip.ParseAddr(candidate)
			if err != nil || !address.Is6() || address.IsUnspecified() || address.IsLoopback() {
				return candidate
			}

			return "2001:db8::200"
		},
	)
}

func isCredentialField(lower string, value string) bool {
	if lower == "sshd.auth.passwd" && value == "enabled" {
		return false
	}

	return strings.Contains(lower, "password") || strings.Contains(lower, "passwd") ||
		strings.Contains(lower, "psk") ||
		strings.HasSuffix(lower, ".key") ||
		strings.HasSuffix(lower, "_key") ||
		lower == "authkey"
}

func validateSafeConfig(values configmap.Values) error {
	for key, value := range values {
		for _, candidate := range ipv4Pattern.FindAllString(value, -1) {
			if candidate != unspecifiedIPv4Address && candidate != fixtureIPAddress {
				slog.Warn("configuration sanitization failed", "err", errSourceIPv4Address)

				return fmt.Errorf("configuration key %q %w", key, errSourceIPv4Address)
			}
		}

		for _, candidate := range macPattern.FindAllString(value, -1) {
			if candidate != "02:00:00:00:00:10" {
				slog.Warn("configuration sanitization failed", "err", errSourceMACAddress)

				return fmt.Errorf("configuration key %q %w", key, errSourceMACAddress)
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
