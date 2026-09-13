// Package network defines typed UniFi device configuration and snapshots.
package network

import (
	"fmt"
	"unicode/utf8"
)

type (
	// DeviceID identifies a UniFi device.
	DeviceID string
	// ConfigVersion identifies an applied configuration revision.
	ConfigVersion string
	// DeviceFamily identifies a supported device family.
	DeviceFamily string
	// VLANID identifies an IEEE 802.1Q virtual LAN.
	VLANID uint16
	// SecretFile is a path to a file containing secret data.
	SecretFile string
	// RadioBand identifies a WiFi frequency band.
	RadioBand string
	// WiFiSecurityMode identifies a WiFi authentication mode.
	WiFiSecurityMode string
	// ChannelWidthMHz is a radio channel width in megahertz.
	ChannelWidthMHz uint16
	// PowerMode identifies automatic or explicit radio power control.
	PowerMode string
	// PoEMode identifies a Power over Ethernet request.
	PoEMode string
)

const (
	// FamilyAP identifies an access point.
	FamilyAP DeviceFamily = "ap"
	// FamilySwitch identifies a switch.
	FamilySwitch DeviceFamily = "switch"

	// Band2GHz identifies the 2.4 GHz radio band.
	Band2GHz RadioBand = "2.4ghz"
	// Band5GHz identifies the 5 GHz radio band.
	Band5GHz RadioBand = "5ghz"

	// WPA2Personal identifies WPA2 personal security.
	WPA2Personal WiFiSecurityMode = "wpa2-personal"

	// Width20 identifies a 20 MHz channel.
	Width20 ChannelWidthMHz = 20
	// Width40 identifies a 40 MHz channel.
	Width40 ChannelWidthMHz = 40

	// PowerAuto delegates radio power selection to the device.
	PowerAuto PowerMode = "auto"
	// PowerExplicit applies the configured dBm value.
	PowerExplicit PowerMode = "explicit"

	// PoEAuto delegates Power over Ethernet selection to the switch.
	PoEAuto PoEMode = "auto"
	// PoEOff disables Power over Ethernet.
	PoEOff PoEMode = "off"
)

// WiFiSecurity configures WiFi authentication.
type WiFiSecurity struct {
	Mode WiFiSecurityMode `json:"mode"`
	PSK  SecretFile       `json:"psk"`
}

// WiFiNetwork configures one broadcast WiFi network.
type WiFiNetwork struct {
	Name     string       `json:"name"`
	Enabled  bool         `json:"enabled"`
	VLAN     *VLANID      `json:"vlan"`
	Bands    []RadioBand  `json:"bands"`
	Security WiFiSecurity `json:"security"`
}

// PowerConfig configures radio transmit power.
type PowerConfig struct {
	Mode PowerMode `json:"mode"`
	DBm  *int      `json:"dbm"`
}

// RadioConfig configures one access point radio.
type RadioConfig struct {
	Band     RadioBand       `json:"band"`
	Enabled  bool            `json:"enabled"`
	Channel  *uint16         `json:"channel"`
	WidthMHz ChannelWidthMHz `json:"width_mhz"`
	Power    PowerConfig     `json:"power"`
}

// SSHConfig configures device SSH credentials.
type SSHConfig struct {
	Username string     `json:"username"`
	Password SecretFile `json:"password"`
}

// Config carries complete configuration records for one setparam response.
type Config struct {
	Version    ConfigVersion `json:"version"`
	Management string        `json:"management"`
	System     string        `json:"system"`
}

// Validate rejects configuration records that cannot cross the JSON control transport.
func (config Config) Validate() error {
	if !utf8.ValidString(string(config.Version)) || !utf8.ValidString(config.Management) || !utf8.ValidString(config.System) {
		return &ControlError{Code: InvalidEncoding, Field: ""}
	}
	return nil
}

// APConfig configures an access point.
type APConfig struct {
	CountryCode uint16        `json:"country_code"`
	Networks    []WiFiNetwork `json:"networks"`
	Radios      []RadioConfig `json:"radios"`
	SSH         *SSHConfig    `json:"ssh"`
}

// SwitchPortConfig configures one switch port.
type SwitchPortConfig struct {
	Index       uint16   `json:"index"`
	Enabled     bool     `json:"enabled"`
	NativeVLAN  VLANID   `json:"native_vlan"`
	TaggedVLANs []VLANID `json:"tagged_vlans"`
	PoE         PoEMode  `json:"poe"`
}

// SwitchConfig configures a switch.
type SwitchConfig struct {
	Ports []SwitchPortConfig `json:"ports"`
	SSH   *SSHConfig         `json:"ssh"`
}

// Validate rejects invalid access point configuration.
func (config APConfig) Validate() error {
	if config.CountryCode == 0 {
		return fmt.Errorf("country_code: must be nonzero")
	}

	configuredBands := make(map[RadioBand]struct{}, len(config.Radios))
	for radioIndex, radio := range config.Radios {
		if err := validateRadio(radio, radioIndex, configuredBands); err != nil {
			return err
		}
	}

	networkNames := make(map[string]struct{}, len(config.Networks))
	for networkIndex, network := range config.Networks {
		if err := validateNetwork(network, networkIndex, networkNames, configuredBands); err != nil {
			return err
		}
	}
	if err := validateSSH(config.SSH); err != nil {
		return err
	}

	return nil
}

// Validate rejects invalid switch configuration.
func (config SwitchConfig) Validate() error {
	portIndexes := make(map[uint16]struct{}, len(config.Ports))
	for portIndex, port := range config.Ports {
		path := fmt.Sprintf("ports[%d]", portIndex)
		if port.Index == 0 {
			return fmt.Errorf("%s.index: must be greater than zero", path)
		}
		if _, exists := portIndexes[port.Index]; exists {
			return fmt.Errorf("%s.index: duplicate value %d", path, port.Index)
		}
		portIndexes[port.Index] = struct{}{}
		if !validVLAN(port.NativeVLAN) {
			return fmt.Errorf("%s.native_vlan: must be from 1 through 4094", path)
		}
		seenVLANs := make(map[VLANID]struct{}, len(port.TaggedVLANs))
		for vlanIndex, taggedVLAN := range port.TaggedVLANs {
			vlanPath := fmt.Sprintf("%s.tagged_vlans[%d]", path, vlanIndex)
			if !validVLAN(taggedVLAN) {
				return fmt.Errorf("%s: must be from 1 through 4094", vlanPath)
			}
			if taggedVLAN == port.NativeVLAN {
				return fmt.Errorf("%s: repeats native_vlan", vlanPath)
			}
			if _, exists := seenVLANs[taggedVLAN]; exists {
				return fmt.Errorf("%s: duplicate value %d", vlanPath, taggedVLAN)
			}
			seenVLANs[taggedVLAN] = struct{}{}
		}
		if port.PoE != "" && port.PoE != PoEAuto && port.PoE != PoEOff {
			return fmt.Errorf("%s.poe: unknown value %q", path, port.PoE)
		}
	}
	if err := validateSSH(config.SSH); err != nil {
		return err
	}

	return nil
}

func validateRadio(radio RadioConfig, index int, configuredBands map[RadioBand]struct{}) error {
	path := fmt.Sprintf("radios[%d]", index)
	if !validRadioBand(radio.Band) {
		return fmt.Errorf("%s.band: unknown value %q", path, radio.Band)
	}
	if _, exists := configuredBands[radio.Band]; exists {
		return fmt.Errorf("%s.band: duplicate value %q", path, radio.Band)
	}
	configuredBands[radio.Band] = struct{}{}
	if radio.Channel != nil && *radio.Channel == 0 {
		return fmt.Errorf("%s.channel: must be greater than zero", path)
	}
	if radio.WidthMHz != Width20 && radio.WidthMHz != Width40 {
		return fmt.Errorf("%s.width_mhz: unknown value %d", path, radio.WidthMHz)
	}
	if radio.Power.Mode != PowerAuto && radio.Power.Mode != PowerExplicit {
		return fmt.Errorf("%s.power.mode: unknown value %q", path, radio.Power.Mode)
	}
	if radio.Power.Mode == PowerExplicit && radio.Power.DBm == nil {
		return fmt.Errorf("%s.power.dbm: required for explicit power", path)
	}
	if radio.Power.Mode == PowerAuto && radio.Power.DBm != nil {
		return fmt.Errorf("%s.power.dbm: must be empty for automatic power", path)
	}
	return nil
}

func validateNetwork(
	network WiFiNetwork,
	index int,
	names map[string]struct{},
	configuredBands map[RadioBand]struct{},
) error {
	path := fmt.Sprintf("networks[%d]", index)
	nameLength := len([]byte(network.Name))
	if nameLength < 1 || nameLength > 32 {
		return fmt.Errorf("%s.name: byte length must be from 1 through 32", path)
	}
	if _, exists := names[network.Name]; exists {
		return fmt.Errorf("%s.name: duplicate value %q", path, network.Name)
	}
	names[network.Name] = struct{}{}
	if network.VLAN != nil && !validVLAN(*network.VLAN) {
		return fmt.Errorf("%s.vlan: must be from 1 through 4094", path)
	}
	if network.Enabled && len(network.Bands) == 0 {
		return fmt.Errorf("%s.bands: required for enabled network", path)
	}
	seenBands := make(map[RadioBand]struct{}, len(network.Bands))
	for bandIndex, band := range network.Bands {
		bandPath := fmt.Sprintf("%s.bands[%d]", path, bandIndex)
		if !validRadioBand(band) {
			return fmt.Errorf("%s: unknown value %q", bandPath, band)
		}
		if _, exists := seenBands[band]; exists {
			return fmt.Errorf("%s: duplicate value %q", bandPath, band)
		}
		seenBands[band] = struct{}{}
		if _, exists := configuredBands[band]; !exists {
			return fmt.Errorf("%s: band %q has no radio configuration", bandPath, band)
		}
	}
	if network.Security.Mode != WPA2Personal {
		return fmt.Errorf("%s.security.mode: unknown value %q", path, network.Security.Mode)
	}
	if network.Security.PSK == "" {
		return fmt.Errorf("%s.security.psk: required for WPA2-Personal", path)
	}
	return nil
}

func validateSSH(config *SSHConfig) error {
	if config == nil {
		return nil
	}
	if config.Username == "" {
		return fmt.Errorf("ssh.username: required when ssh is configured")
	}
	if config.Password == "" {
		return fmt.Errorf("ssh.password: required when ssh is configured")
	}
	return nil
}

func validRadioBand(band RadioBand) bool {
	return band == Band2GHz || band == Band5GHz
}

func validVLAN(vlan VLANID) bool {
	return vlan >= 1 && vlan <= 4094
}
