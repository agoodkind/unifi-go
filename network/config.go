// Package network defines typed UniFi device configuration and snapshots.
package network

import (
	"fmt"
	"slices"
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
	// RadioID identifies one physical WiFi radio.
	RadioID string
	// WiFiSecurityMode identifies a WiFi authentication mode.
	WiFiSecurityMode string
	// BSSTransitionMode identifies whether an SSID advertises BSS Transition.
	BSSTransitionMode string
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

	// BSSTransitionEnabled advertises BSS Transition support.
	BSSTransitionEnabled BSSTransitionMode = "enabled"
	// BSSTransitionDisabled suppresses BSS Transition support.
	BSSTransitionDisabled BSSTransitionMode = "disabled"

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
	Mode Optional[WiFiSecurityMode] `json:"mode,omitzero"`
	PSK  Optional[SecretFile]       `json:"psk,omitzero"`
}

// WiFiNetwork configures one broadcast WiFi network.
type WiFiNetwork struct {
	Name          string                      `json:"name"`
	Enabled       Optional[bool]              `json:"enabled,omitzero"`
	VLAN          Optional[VLANID]            `json:"vlan,omitzero"`
	Bands         Optional[[]RadioBand]       `json:"bands,omitzero"`
	RadioIDs      Optional[[]RadioID]         `json:"radio_ids,omitzero"`
	BSSTransition Optional[BSSTransitionMode] `json:"bss_transition,omitzero"`
	Security      Optional[WiFiSecurity]      `json:"security,omitzero"`
}

// PowerConfig configures radio transmit power.
type PowerConfig struct {
	Mode Optional[PowerMode] `json:"mode,omitzero"`
	DBm  Optional[int]       `json:"dbm,omitzero"`
}

// RadioConfig configures one access point radio.
type RadioConfig struct {
	ID       RadioID                   `json:"id,omitempty"`
	Band     RadioBand                 `json:"band"`
	Enabled  Optional[bool]            `json:"enabled,omitzero"`
	Channel  Optional[uint16]          `json:"channel,omitzero"`
	WidthMHz Optional[ChannelWidthMHz] `json:"width_mhz,omitzero"`
	Power    Optional[PowerConfig]     `json:"power,omitzero"`
}

// SSHConfig configures device SSH credentials.
type SSHConfig struct {
	Username Optional[string]     `json:"username,omitzero"`
	Password Optional[SecretFile] `json:"password,omitzero"`
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
	CountryCode Optional[uint16]        `json:"country_code,omitzero"`
	Networks    Optional[[]WiFiNetwork] `json:"networks,omitzero"`
	Radios      Optional[[]RadioConfig] `json:"radios,omitzero"`
	SSH         Optional[SSHConfig]     `json:"ssh,omitzero"`
}

// Clone returns an independent copy of the access point configuration.
func (config APConfig) Clone() APConfig {
	result := config
	result.Networks.Value = slices.Clone(config.Networks.Value)
	for index := range result.Networks.Value {
		result.Networks.Value[index].Bands.Value = slices.Clone(config.Networks.Value[index].Bands.Value)
		result.Networks.Value[index].RadioIDs.Value = slices.Clone(config.Networks.Value[index].RadioIDs.Value)
	}
	result.Radios.Value = slices.Clone(config.Radios.Value)
	return result
}

// SwitchPortConfig configures one switch port.
type SwitchPortConfig struct {
	Index       uint16             `json:"index"`
	Enabled     Optional[bool]     `json:"enabled,omitzero"`
	NativeVLAN  Optional[VLANID]   `json:"native_vlan,omitzero"`
	TaggedVLANs Optional[[]VLANID] `json:"tagged_vlans,omitzero"`
	PoE         Optional[PoEMode]  `json:"poe,omitzero"`
}

// SwitchConfig configures a switch.
type SwitchConfig struct {
	Ports Optional[[]SwitchPortConfig] `json:"ports,omitzero"`
	SSH   Optional[SSHConfig]          `json:"ssh,omitzero"`
}

// Clone returns an independent copy of the switch configuration.
func (config SwitchConfig) Clone() SwitchConfig {
	result := config
	result.Ports.Value = slices.Clone(config.Ports.Value)
	for index := range result.Ports.Value {
		result.Ports.Value[index].TaggedVLANs.Value = slices.Clone(config.Ports.Value[index].TaggedVLANs.Value)
	}
	return result
}

// Validate rejects invalid access point configuration.
func (config APConfig) Validate() error {
	if config.CountryCode.Null {
		return fmt.Errorf("country_code: null is not supported")
	}
	if config.CountryCode.Present && config.CountryCode.Value == 0 {
		return fmt.Errorf("country_code: must be nonzero")
	}

	configuredBands := make(map[RadioBand]struct{})
	configuredRadioIDs := make(map[RadioID]struct{})
	if config.Radios.Null {
		return fmt.Errorf("radios: null is not supported")
	}
	if config.Radios.Present {
		configuredBands = make(map[RadioBand]struct{}, len(config.Radios.Value))
		bandCounts := make(map[RadioBand]int, len(config.Radios.Value))
		for _, radio := range config.Radios.Value {
			bandCounts[radio.Band]++
		}
		for radioIndex, radio := range config.Radios.Value {
			if err := validateRadio(radio, radioIndex, bandCounts, configuredBands, configuredRadioIDs); err != nil {
				return err
			}
		}
	}

	if config.Networks.Null {
		return fmt.Errorf("networks: null is not supported")
	}
	if config.Networks.Present {
		networkNames := make(map[string]struct{}, len(config.Networks.Value))
		for networkIndex, wifi := range config.Networks.Value {
			if err := validateNetwork(wifi, networkIndex, networkNames, configuredBands, configuredRadioIDs, config.Radios.Present); err != nil {
				return err
			}
		}
	}
	if err := validateSSH(config.SSH, "ssh"); err != nil {
		return err
	}

	return nil
}

// Validate rejects invalid switch configuration.
func (config SwitchConfig) Validate() error {
	if config.Ports.Null {
		return fmt.Errorf("ports: null is not supported")
	}
	if !config.Ports.Present {
		return validateSSH(config.SSH, "ssh")
	}
	portIndexes := make(map[uint16]struct{}, len(config.Ports.Value))
	for portIndex, port := range config.Ports.Value {
		path := fmt.Sprintf("ports[%d]", portIndex)
		if port.Index == 0 {
			return fmt.Errorf("%s.index: must be greater than zero", path)
		}
		if _, exists := portIndexes[port.Index]; exists {
			return fmt.Errorf("%s.index: duplicate value %d", path, port.Index)
		}
		portIndexes[port.Index] = struct{}{}
		if port.Enabled.Null || port.NativeVLAN.Null || port.TaggedVLANs.Null || port.PoE.Null {
			return fmt.Errorf("%s: null is not supported", path)
		}
		if port.NativeVLAN.Present && !validVLAN(port.NativeVLAN.Value) {
			return fmt.Errorf("%s.native_vlan: must be from 1 through 4094", path)
		}
		seenVLANs := make(map[VLANID]struct{}, len(port.TaggedVLANs.Value))
		for vlanIndex, taggedVLAN := range port.TaggedVLANs.Value {
			vlanPath := fmt.Sprintf("%s.tagged_vlans[%d]", path, vlanIndex)
			if !validVLAN(taggedVLAN) {
				return fmt.Errorf("%s: must be from 1 through 4094", vlanPath)
			}
			if port.NativeVLAN.Present && taggedVLAN == port.NativeVLAN.Value {
				return fmt.Errorf("%s: repeats native_vlan", vlanPath)
			}
			if _, exists := seenVLANs[taggedVLAN]; exists {
				return fmt.Errorf("%s: duplicate value %d", vlanPath, taggedVLAN)
			}
			seenVLANs[taggedVLAN] = struct{}{}
		}
		if port.PoE.Present && port.PoE.Value != "" && port.PoE.Value != PoEAuto && port.PoE.Value != PoEOff {
			return fmt.Errorf("%s.poe: unknown value %q", path, port.PoE.Value)
		}
	}
	if err := validateSSH(config.SSH, "ssh"); err != nil {
		return err
	}

	return nil
}

func validateRadio(radio RadioConfig, index int, bandCounts map[RadioBand]int, configuredBands map[RadioBand]struct{}, configuredRadioIDs map[RadioID]struct{}) error {
	path := fmt.Sprintf("radios[%d]", index)
	if !validRadioBand(radio.Band) {
		return fmt.Errorf("%s.band: unknown value %q", path, radio.Band)
	}
	if bandCounts[radio.Band] > 1 && radio.ID == "" {
		return fmt.Errorf("%s.id: required when band %q has multiple radios", path, radio.Band)
	}
	if radio.ID != "" {
		if _, exists := configuredRadioIDs[radio.ID]; exists {
			return fmt.Errorf("%s.id: duplicate value", path)
		}
		configuredRadioIDs[radio.ID] = struct{}{}
	}
	configuredBands[radio.Band] = struct{}{}
	if radio.Enabled.Null || radio.WidthMHz.Null || radio.Power.Null {
		return fmt.Errorf("%s: null is not supported", path)
	}
	if radio.Channel.Present && !radio.Channel.Null && radio.Channel.Value == 0 {
		return fmt.Errorf("%s.channel: must be greater than zero", path)
	}
	if radio.WidthMHz.Present && radio.WidthMHz.Value != Width20 && radio.WidthMHz.Value != Width40 {
		return fmt.Errorf("%s.width_mhz: unknown value %d", path, radio.WidthMHz.Value)
	}
	if !radio.Power.Present {
		return nil
	}
	power := radio.Power.Value
	if power.Mode.Null || power.DBm.Null {
		return fmt.Errorf("%s.power: null is not supported", path)
	}
	if power.Mode.Present && power.Mode.Value != PowerAuto && power.Mode.Value != PowerExplicit {
		return fmt.Errorf("%s.power.mode: unknown value %q", path, power.Mode.Value)
	}
	if power.Mode.Present && power.Mode.Value == PowerAuto && power.DBm.Present {
		return fmt.Errorf("%s.power.dbm: must be empty for automatic power", path)
	}
	return nil
}

func validateNetwork(
	network WiFiNetwork,
	index int,
	names map[string]struct{},
	configuredBands map[RadioBand]struct{},
	configuredRadioIDs map[RadioID]struct{},
	checkConfiguredBands bool,
) error {
	path := fmt.Sprintf("networks[%d]", index)
	if err := validateNetworkIdentity(network, path, names); err != nil {
		return err
	}
	if network.Enabled.Null || network.Bands.Null || network.RadioIDs.Null || network.BSSTransition.Null || network.Security.Null {
		return fmt.Errorf("%s: null is not supported", path)
	}
	if network.VLAN.Present && !network.VLAN.Null && !validVLAN(network.VLAN.Value) {
		return fmt.Errorf("%s.vlan: must be from 1 through 4094", path)
	}
	if err := validateNetworkSelectors(network, path, configuredBands, configuredRadioIDs, checkConfiguredBands); err != nil {
		return err
	}
	if network.BSSTransition.Present && network.BSSTransition.Value != BSSTransitionEnabled && network.BSSTransition.Value != BSSTransitionDisabled {
		return fmt.Errorf("%s.bss_transition: unknown value %q", path, network.BSSTransition.Value)
	}
	return validateWiFiSecurity(network.Security, path)
}

func validateNetworkIdentity(network WiFiNetwork, path string, names map[string]struct{}) error {
	nameLength := len([]byte(network.Name))
	if nameLength < 1 || nameLength > 32 {
		return fmt.Errorf("%s.name: byte length must be from 1 through 32", path)
	}
	if _, exists := names[network.Name]; exists {
		return fmt.Errorf("%s.name: duplicate value %q", path, network.Name)
	}
	names[network.Name] = struct{}{}
	return nil
}

func validateNetworkSelectors(network WiFiNetwork, path string, configuredBands map[RadioBand]struct{}, configuredRadioIDs map[RadioID]struct{}, checkConfigured bool) error {
	if network.Bands.Present && network.RadioIDs.Present {
		return fmt.Errorf("%s: bands and radio_ids are mutually exclusive", path)
	}
	if network.Enabled.Present && network.Enabled.Value && network.Bands.Present && len(network.Bands.Value) == 0 {
		return fmt.Errorf("%s.bands: required for enabled network", path)
	}
	if network.Enabled.Present && network.Enabled.Value && network.RadioIDs.Present && len(network.RadioIDs.Value) == 0 {
		return fmt.Errorf("%s.radio_ids: required for enabled network", path)
	}
	if err := validateNetworkBands(network.Bands.Value, path, configuredBands, checkConfigured); err != nil {
		return err
	}
	return validateNetworkRadioIDs(network.RadioIDs.Value, path, configuredRadioIDs, checkConfigured)
}

func validateNetworkBands(bands []RadioBand, path string, configuredBands map[RadioBand]struct{}, checkConfigured bool) error {
	seenBands := make(map[RadioBand]struct{}, len(bands))
	for bandIndex, band := range bands {
		bandPath := fmt.Sprintf("%s.bands[%d]", path, bandIndex)
		if !validRadioBand(band) {
			return fmt.Errorf("%s: unknown value %q", bandPath, band)
		}
		if _, exists := seenBands[band]; exists {
			return fmt.Errorf("%s: duplicate value %q", bandPath, band)
		}
		seenBands[band] = struct{}{}
		if _, exists := configuredBands[band]; checkConfigured && !exists {
			return fmt.Errorf("%s: band %q has no radio configuration", bandPath, band)
		}
	}
	return nil
}

func validateNetworkRadioIDs(radioIDs []RadioID, path string, configuredRadioIDs map[RadioID]struct{}, checkConfigured bool) error {
	seenRadioIDs := make(map[RadioID]struct{}, len(radioIDs))
	for radioIndex, radioID := range radioIDs {
		radioPath := fmt.Sprintf("%s.radio_ids[%d]", path, radioIndex)
		if radioID == "" {
			return fmt.Errorf("%s: must not be empty", radioPath)
		}
		if _, exists := seenRadioIDs[radioID]; exists {
			return fmt.Errorf("%s: duplicate value", radioPath)
		}
		seenRadioIDs[radioID] = struct{}{}
		if _, exists := configuredRadioIDs[radioID]; checkConfigured && !exists {
			return fmt.Errorf("%s: no radio configuration", radioPath)
		}
	}
	return nil
}

func validateWiFiSecurity(securityConfig Optional[WiFiSecurity], path string) error {
	if !securityConfig.Present {
		return nil
	}
	security := securityConfig.Value
	if security.Mode.Null || security.PSK.Null {
		return fmt.Errorf("%s.security: null is not supported", path)
	}
	if security.Mode.Present && security.Mode.Value != WPA2Personal {
		return fmt.Errorf("%s.security.mode: unknown value %q", path, security.Mode.Value)
	}
	if security.PSK.Present && security.PSK.Value == "" {
		return fmt.Errorf("%s.security.psk: required for WPA2-Personal", path)
	}
	return nil
}

func validateSSH(config Optional[SSHConfig], path string) error {
	if config.Null {
		return fmt.Errorf("%s: null is not supported", path)
	}
	if !config.Present {
		return nil
	}
	if config.Value.Username.Null || config.Value.Password.Null {
		return fmt.Errorf("%s: null is not supported", path)
	}
	if config.Value.Username.Present && config.Value.Username.Value == "" {
		return fmt.Errorf("ssh.username: required when ssh is configured")
	}
	if config.Value.Password.Present && config.Value.Password.Value == "" {
		return fmt.Errorf("ssh.password: required when ssh is configured")
	}
	return nil
}

// ValidateComplete requires a complete typed access point projection.
func (config APConfig) ValidateComplete() error {
	if err := config.Validate(); err != nil {
		return err
	}
	for _, field := range []struct {
		present bool
		path    string
	}{
		{config.CountryCode.Present, "country_code"},
		{config.Networks.Present, "networks"},
		{config.Radios.Present, "radios"},
	} {
		if !field.present {
			return requiredPolicy(field.path)
		}
	}
	for index, radio := range config.Radios.Value {
		path := fmt.Sprintf("radios[%d]", index)
		for _, field := range []struct {
			present bool
			path    string
		}{
			{radio.Enabled.Present, path + ".enabled"},
			{radio.Channel.Present, path + ".channel"},
			{radio.WidthMHz.Present, path + ".width_mhz"},
			{radio.Power.Present, path + ".power"},
		} {
			if !field.present {
				return requiredPolicy(field.path)
			}
		}
		if !radio.Power.Value.Mode.Present {
			return requiredPolicy(path + ".power.mode")
		}
		if radio.Power.Value.Mode.Value == PowerExplicit && !radio.Power.Value.DBm.Present {
			return requiredPolicy(path + ".power.dbm")
		}
	}
	for index, wifi := range config.Networks.Value {
		path := fmt.Sprintf("networks[%d]", index)
		for _, field := range []struct {
			present bool
			path    string
		}{
			{wifi.Enabled.Present, path + ".enabled"},
			{wifi.VLAN.Present, path + ".vlan"},
			{wifi.BSSTransition.Present, path + ".bss_transition"},
			{wifi.Security.Present, path + ".security"},
		} {
			if !field.present {
				return requiredPolicy(field.path)
			}
		}
		if err := validateCompleteNetworkSelector(wifi, path); err != nil {
			return err
		}
		if !wifi.Security.Value.Mode.Present {
			return requiredPolicy(path + ".security.mode")
		}
		if !wifi.Security.Value.PSK.Present {
			return requiredPolicy(path + ".security.psk")
		}
	}
	return validateCompleteSSH(config.SSH)
}

func validateCompleteNetworkSelector(wifi WiFiNetwork, path string) error {
	if wifi.Bands.Present && len(wifi.Bands.Value) > 0 {
		return nil
	}
	if wifi.RadioIDs.Present && len(wifi.RadioIDs.Value) > 0 {
		return nil
	}
	if wifi.RadioIDs.Present {
		return requiredPolicy(path + ".radio_ids")
	}
	return requiredPolicy(path + ".bands")
}

// ValidateComplete requires a complete typed switch projection.
func (config SwitchConfig) ValidateComplete() error {
	if err := config.Validate(); err != nil {
		return err
	}
	if !config.Ports.Present {
		return requiredPolicy("ports")
	}
	for index, port := range config.Ports.Value {
		path := fmt.Sprintf("ports[%d]", index)
		for _, field := range []struct {
			present bool
			path    string
		}{
			{port.Enabled.Present, path + ".enabled"},
			{port.NativeVLAN.Present, path + ".native_vlan"},
			{port.TaggedVLANs.Present, path + ".tagged_vlans"},
			{port.PoE.Present, path + ".poe"},
		} {
			if !field.present {
				return requiredPolicy(field.path)
			}
		}
	}
	return validateCompleteSSH(config.SSH)
}

func validateCompleteSSH(config Optional[SSHConfig]) error {
	if !config.Present {
		return nil
	}
	if !config.Value.Username.Present {
		return requiredPolicy("ssh.username")
	}
	if !config.Value.Password.Present {
		return requiredPolicy("ssh.password")
	}
	return nil
}

func requiredPolicy(field string) error {
	return &ControlError{Code: PolicyRequired, Field: field}
}

func validRadioBand(band RadioBand) bool {
	return band == Band2GHz || band == Band5GHz
}

func validVLAN(vlan VLANID) bool {
	return vlan >= 1 && vlan <= 4094
}
