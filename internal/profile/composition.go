package profile

import (
	"slices"
	"strconv"
	"strings"

	"goodkind.io/unifi-go/internal/configmap"
	"goodkind.io/unifi-go/network"
)

// CompilationInput supplies the full baseline and its prior typed projection.
type CompilationInput struct {
	Baseline SetParam
	AP       *network.APConfig
	Switch   *network.SwitchConfig
	Bindings []ResourceBinding
}

// Compilation contains the composed baseline and its independent typed projection.
type Compilation struct {
	Param    SetParam
	AP       *network.APConfig
	Switch   *network.SwitchConfig
	Bindings []ResourceBinding
}

// CloneBaseline verifies both namespaces before returning independent maps.
func CloneBaseline(input CompilationInput) (SetParam, error) {
	if len(input.Baseline.Management) == 0 || len(input.Baseline.System) == 0 {
		return SetParam{}, &network.ControlError{Code: network.BaselineRequired}
	}
	if _, err := input.Baseline.Management.Encode(); err != nil {
		return SetParam{}, UnusableBaseline()
	}
	if _, err := input.Baseline.System.Encode(); err != nil {
		return SetParam{}, UnusableBaseline()
	}
	return SetParam{Version: "", Management: input.Baseline.Management.Clone(), System: input.Baseline.System.Clone()}, nil
}

// UnusableBaseline returns a body-free ownership error.
func UnusableBaseline() error { return &network.ControlError{Code: network.BaselineUnusable} }

// CloneBindings copies nested prefix slices and orders identities deterministically.
func CloneBindings(bindings []ResourceBinding) []ResourceBinding {
	result := slices.Clone(bindings)
	for index := range result {
		result[index].Prefixes = slices.Clone(result[index].Prefixes)
	}
	slices.SortFunc(result, func(left, right ResourceBinding) int {
		return strings.Compare(left.Kind+"\x00"+left.Identity+"\x00"+left.RadioID, right.Kind+"\x00"+right.Identity+"\x00"+right.RadioID)
	})
	return result
}

// RecordPrefixes returns only immediate numbered records in a namespace.
func RecordPrefixes(values configmap.Values, namespace string) []string {
	var result []string
	for key := range values {
		suffix, found := strings.CutPrefix(key, namespace)
		if !found {
			continue
		}
		number, _, found := strings.Cut(suffix, ".")
		if !found {
			continue
		}
		index, err := strconv.Atoi(number)
		if err != nil || index < 1 {
			continue
		}
		result = append(result, namespace+number+".")
	}
	slices.Sort(result)
	return slices.Compact(result)
}

// MatchRecord resolves one exact record, rejecting duplicate identity matches.
func MatchRecord(values configmap.Values, namespace, field, value string) (string, error) {
	var result string
	for _, prefix := range RecordPrefixes(values, namespace) {
		if values[prefix+field] != value {
			continue
		}
		if result != "" {
			return "", UnusableBaseline()
		}
		result = prefix
	}
	return result, nil
}

// NextRecord returns an unused numbered prefix without moving existing records.
func NextRecord(values configmap.Values, namespace string) string {
	occupied := RecordPrefixes(values, namespace)
	for index := 1; ; index++ {
		prefix := namespace + strconv.Itoa(index) + "."
		if !slices.Contains(occupied, prefix) {
			return prefix
		}
	}
}

// CopyBindingRecords copies all owned keys and remaps only named reference fields.
func CopyBindingRecords(values configmap.Values, prefixes map[string]string, references map[string]string) {
	before := values.Clone()
	for oldPrefix, newPrefix := range prefixes {
		for key, value := range before {
			suffix, found := strings.CutPrefix(key, oldPrefix)
			if !found {
				continue
			}
			if suffix == "devname" || suffix == "parent" || suffix == "ssid" || suffix == "br.devname" {
				if replacement, exists := references[value]; exists {
					value = replacement
				}
			}
			values[newPrefix+suffix] = value
		}
	}
}

// DeleteRecord removes exactly one owned record, including its unknown keys.
func DeleteRecord(values configmap.Values, prefix string) {
	for key := range values {
		if strings.HasPrefix(key, prefix) {
			delete(values, key)
		}
	}
}

func overlay[T interface {
	~bool | ~string | ~uint16 | ~int |
		[]network.RadioBand | []network.VLANID | []network.WiFiNetwork | []network.RadioConfig | []network.SwitchPortConfig |
		network.WiFiSecurity | network.PowerConfig | network.SSHConfig
}](prior, supplied network.Optional[T]) network.Optional[T] {
	if supplied.Present {
		return supplied
	}
	return prior
}

// MergeSSH preserves individually omitted credential fields.
func MergeSSH(prior, supplied network.Optional[network.SSHConfig]) network.Optional[network.SSHConfig] {
	if !supplied.Present {
		return prior
	}
	result := supplied
	result.Value.Username = overlay(prior.Value.Username, supplied.Value.Username)
	result.Value.Password = overlay(prior.Value.Password, supplied.Value.Password) // gitleaks:allow
	return result
}

// MergeAP composes presence-aware policy and copies every nested collection.
func MergeAP(prior *network.APConfig, request network.APConfig) network.APConfig {
	var result network.APConfig
	if prior != nil {
		result = *prior
	}
	result.CountryCode = overlay(result.CountryCode, request.CountryCode)
	result.SSH = MergeSSH(result.SSH, request.SSH)
	oldNetworks, oldRadios := result.Networks.Value, result.Radios.Value
	result.Networks = overlay(result.Networks, request.Networks)
	result.Radios = overlay(result.Radios, request.Radios)
	result.Networks.Value = slices.Clone(result.Networks.Value)
	result.Radios.Value = slices.Clone(result.Radios.Value)

	for index, wifi := range result.Networks.Value {
		if request.Networks.Present {
			wifi = mergeWiFi(oldNetworks, wifi)
		}
		wifi.Bands.Value = slices.Clone(wifi.Bands.Value)
		result.Networks.Value[index] = wifi
	}
	for index, radio := range result.Radios.Value {
		if request.Radios.Present {
			radio = mergeRadio(oldRadios, radio)
		}
		result.Radios.Value[index] = radio
	}
	return result
}

// MergeSwitch composes presence-aware port policy without sharing slices.
func MergeSwitch(prior *network.SwitchConfig, request network.SwitchConfig) network.SwitchConfig {
	var result network.SwitchConfig
	if prior != nil {
		result = *prior
	}
	result.SSH = MergeSSH(result.SSH, request.SSH)
	oldPorts := result.Ports.Value
	result.Ports = overlay(result.Ports, request.Ports)
	result.Ports.Value = slices.Clone(result.Ports.Value)
	for index, port := range result.Ports.Value {
		if request.Ports.Present {
			for _, old := range oldPorts {
				if old.Index != port.Index {
					continue
				}
				port.Enabled = overlay(old.Enabled, port.Enabled)
				port.NativeVLAN = overlay(old.NativeVLAN, port.NativeVLAN)
				port.TaggedVLANs = overlay(old.TaggedVLANs, port.TaggedVLANs)
				port.PoE = overlay(old.PoE, port.PoE)
			}
		}
		port.TaggedVLANs.Value = slices.Clone(port.TaggedVLANs.Value)
		result.Ports.Value[index] = port
	}
	return result
}

func mergeWiFi(prior []network.WiFiNetwork, wifi network.WiFiNetwork) network.WiFiNetwork {
	for _, old := range prior {
		if old.Name != wifi.Name {
			continue
		}
		wifi.Enabled = overlay(old.Enabled, wifi.Enabled)
		wifi.VLAN = overlay(old.VLAN, wifi.VLAN)
		wifi.Bands = overlay(old.Bands, wifi.Bands)
		wifi.BSSTransition = overlay(old.BSSTransition, wifi.BSSTransition)
		security := wifi.Security
		wifi.Security = overlay(old.Security, security)
		if security.Present {
			wifi.Security.Value.Mode = overlay(old.Security.Value.Mode, security.Value.Mode)
			wifi.Security.Value.PSK = overlay(old.Security.Value.PSK, security.Value.PSK)
		}
	}
	return wifi
}

func mergeRadio(prior []network.RadioConfig, radio network.RadioConfig) network.RadioConfig {
	for _, old := range prior {
		if old.Band != radio.Band {
			continue
		}
		radio.Enabled = overlay(old.Enabled, radio.Enabled)
		radio.Channel = overlay(old.Channel, radio.Channel)
		radio.WidthMHz = overlay(old.WidthMHz, radio.WidthMHz)
		power := radio.Power
		radio.Power = overlay(old.Power, power)
		if !power.Present {
			continue
		}
		radio.Power.Value.Mode = overlay(old.Power.Value.Mode, power.Value.Mode)
		radio.Power.Value.DBm = overlay(old.Power.Value.DBm, power.Value.DBm)
		if power.Value.Mode.Present && power.Value.Mode.Value == network.PowerAuto {
			radio.Power.Value.DBm = network.Optional[int]{}
		}
	}
	return radio
}
