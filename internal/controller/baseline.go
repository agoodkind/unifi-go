package controller

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"goodkind.io/unifi-go/internal/configmap"
	"goodkind.io/unifi-go/internal/profile"
	"goodkind.io/unifi-go/network"
)

const baselineSchemaVersion uint16 = 1

func (c *Controller) importBaseline(id network.DeviceID, imported *network.BaselineImport) error {
	if imported == nil || imported.AP != nil && imported.Switch != nil {
		return &network.ControlError{Code: network.InvalidConfig}
	}
	if err := imported.Config.Validate(); err != nil {
		return &network.ControlError{Code: network.InvalidEncoding}
	}
	if imported.Config.Version == "" || imported.Config.Management == "" || imported.Config.System == "" {
		return &network.ControlError{Code: network.BaselineUnusable}
	}
	management, err := configmap.Parse(imported.Config.Management)
	if err != nil {
		return &network.ControlError{Code: network.BaselineUnusable}
	}
	system, err := configmap.Parse(imported.Config.System)
	if err != nil {
		return &network.ControlError{Code: network.BaselineUnusable}
	}
	mac, err := normalizeMAC(string(id))
	if err != nil {
		return &network.ControlError{Code: network.InvalidDevice}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	device, exists := c.devices[mac]
	if !exists {
		return &network.ControlError{Code: network.NotRegistered}
	}
	if device.NextKey != "" {
		return &network.ControlError{Code: network.AdoptionPending}
	}
	if device.Descriptor == nil {
		return &network.ControlError{Code: network.NoReport}
	}
	typedReady := imported.AP != nil || imported.Switch != nil
	var compilation profile.Compilation
	if typedReady {
		input := profile.CompilationInput{Baseline: profile.SetParam{Version: imported.Config.Version, Management: management, System: system}, AP: imported.AP, Switch: imported.Switch, Bindings: nil, WiFiCopies: cloneWiFiCopies(device.wifiCopies)}
		compilation, err = c.validateBaselineProjection(*device.Descriptor, input)
		if err != nil {
			return err
		}
	}
	previous := device
	device.Baseline = &ConfigurationBaseline{SchemaVersion: baselineSchemaVersion, Config: imported.Config, TypedReady: typedReady, Bindings: profile.CloneBindings(compilation.Bindings)}
	device.DesiredAP, device.DesiredSwitch = compilation.AP, compilation.Switch
	device.DesiredVersion = imported.Config.Version
	c.devices[mac] = device
	if err := c.saveLocked(); err != nil {
		c.devices[mac] = previous
		return &network.ControlError{Code: network.PersistenceFailed}
	}
	return nil
}

func (c *Controller) validateBaselineProjection(descriptor profile.DeviceDescriptor, input profile.CompilationInput) (profile.Compilation, error) {
	switch descriptor.Family {
	case network.FamilyAP:
		if input.Switch != nil {
			return profile.Compilation{}, &network.ControlError{Code: network.FamilyMismatch}
		}
		if err := validateAPProjection(input.AP); err != nil {
			return profile.Compilation{}, err
		}
		result, err := c.registry.CompileAP(descriptor, input, network.APConfig{}, fileSecrets{})
		if err != nil {
			return profile.Compilation{}, compilerFailure(err)
		}
		return result, nil
	case network.FamilySwitch:
		if input.AP != nil {
			return profile.Compilation{}, &network.ControlError{Code: network.FamilyMismatch}
		}
		if input.Switch != nil {
			if err := input.Switch.Validate(); err != nil {
				return profile.Compilation{}, compilerFailure(err)
			}
			for _, port := range input.Switch.Ports.Value {
				if !uniquePortCapability(descriptor.Ports, port.Index) || !hasSwitchPortIdentity(input.Baseline.System, fmt.Sprintf("switch.port.%d.", port.Index)) {
					return profile.Compilation{}, &network.ControlError{Code: network.BaselineUnusable}
				}
			}
		}
		result, err := c.registry.CompileSwitch(descriptor, input, network.SwitchConfig{}, fileSecrets{})
		if err != nil {
			return profile.Compilation{}, compilerFailure(err)
		}
		return result, nil
	default:
		return profile.Compilation{}, &network.ControlError{Code: network.FamilyMismatch}
	}
}

func validateAPProjection(config *network.APConfig) error {
	if config == nil {
		return nil
	}
	if err := config.Validate(); err != nil {
		return compilerFailure(err)
	}
	for _, wifi := range config.Networks.Value {
		if wifi.Bands.Present && len(wifi.Bands.Value) == 0 {
			return &network.ControlError{Code: network.BaselineUnusable}
		}
		if !wifi.Bands.Present && (!wifi.RadioIDs.Present || len(wifi.RadioIDs.Value) == 0) {
			return &network.ControlError{Code: network.BaselineUnusable}
		}
	}
	return nil
}

// ConfigurationBaseline persists exact configuration text and typed ownership.
type ConfigurationBaseline struct {
	SchemaVersion uint16                    `json:"schema_version"`
	Config        network.Config            `json:"config"`
	TypedReady    bool                      `json:"typed_ready"`
	Bindings      []profile.ResourceBinding `json:"bindings,omitempty"`
}

func baselineFromRawReply(reply Reply) *ConfigurationBaseline {
	return &ConfigurationBaseline{
		SchemaVersion: baselineSchemaVersion,
		Config: network.Config{
			Version:    network.ConfigVersion(reply.ConfigVersion),
			Management: reply.ManagementConfig,
			System:     reply.SystemConfig,
		},
		TypedReady: false,
		Bindings:   nil,
	}
}

func baselineFromLegacy(device Device) (*ConfigurationBaseline, error) {
	if device.LastSetParam == nil {
		return nil, fmt.Errorf("last setparam is absent")
	}
	reply := device.LastSetParam
	baseline := baselineFromRawReply(*reply)
	management, managementOK := parseLegacyConfig(reply.ManagementConfig)
	if !managementOK {
		return baseline, nil
	}
	system, systemOK := parseLegacyConfig(reply.SystemConfig)
	if !systemOK {
		return baseline, nil
	}
	complete := reply.ManagementConfig != "" && reply.SystemConfig != ""
	versionsMatch := device.DesiredVersion != "" && string(device.DesiredVersion) == reply.ConfigVersion
	if !complete || !versionsMatch {
		return baseline, nil
	}
	bindings, ok := baselineBindings(device, management, system)
	if !ok {
		return baseline, nil
	}
	baseline.TypedReady = true
	baseline.Bindings = bindings
	return baseline, nil
}

func parseLegacyConfig(raw string) (configmap.Values, bool) {
	values, err := configmap.Parse(raw)
	if err != nil {
		return nil, false
	}
	return values, true
}

func baselineBindings(device Device, management, system configmap.Values) ([]profile.ResourceBinding, bool) {
	if management["cfgversion"] != string(device.DesiredVersion) || device.Descriptor == nil {
		return nil, false
	}
	if device.DesiredAP != nil && device.DesiredSwitch == nil {
		return apBaselineBindings(*device.DesiredAP, *device.Descriptor, system)
	}
	if device.DesiredSwitch != nil && device.DesiredAP == nil {
		return switchBaselineBindings(*device.DesiredSwitch, *device.Descriptor, system)
	}
	return nil, false
}

func apBaselineBindings(config network.APConfig, descriptor profile.DeviceDescriptor, system configmap.Values) ([]profile.ResourceBinding, bool) {
	if descriptor.Family != network.FamilyAP || config.ValidateComplete() != nil {
		return nil, false
	}
	bindings := make([]profile.ResourceBinding, 0, len(config.Radios.Value)+len(config.Networks.Value))
	for _, radio := range config.Radios.Value {
		capability, ok := uniqueRadioCapability(descriptor.Radios, radio.Band)
		if !ok {
			return nil, false
		}
		prefix, ok := uniqueRecordPrefix(system, "radio.", ".phyname", capability.Interface)
		if !ok {
			return nil, false
		}
		bindings = append(bindings, profile.ResourceBinding{Kind: "radio", Identity: string(radio.Band), RadioID: capability.ID, Prefixes: []string{prefix}})
	}
	for _, wifi := range config.Networks.Value {
		for _, band := range wifi.Bands.Value {
			capability, ok := uniqueRadioCapability(descriptor.Radios, band)
			if !ok {
				return nil, false
			}
			wirelessPrefixes := matchingWirelessPrefixes(system, wifi.Name, capability.Interface)
			if len(wirelessPrefixes) != 1 {
				return nil, false
			}
			deviceName, ok := system[wirelessPrefixes[0]+"devname"]
			if !ok || deviceName == "" {
				return nil, false
			}
			aaaPrefixes := matchingAAAPrefixes(system, wifi.Name, deviceName)
			if len(aaaPrefixes) != 1 {
				return nil, false
			}
			bindings = append(bindings, profile.ResourceBinding{Kind: "wifi", Identity: wifi.Name, RadioID: capability.ID, Prefixes: []string{wirelessPrefixes[0], aaaPrefixes[0]}})
		}
	}
	return bindings, true
}

func switchBaselineBindings(config network.SwitchConfig, descriptor profile.DeviceDescriptor, system configmap.Values) ([]profile.ResourceBinding, bool) {
	if descriptor.Family != network.FamilySwitch || config.ValidateComplete() != nil {
		return nil, false
	}
	bindings := make([]profile.ResourceBinding, 0, len(config.Ports.Value))
	for _, port := range config.Ports.Value {
		if !uniquePortCapability(descriptor.Ports, port.Index) {
			return nil, false
		}
		prefix := fmt.Sprintf("switch.port.%d.", port.Index)
		if !hasSwitchPortIdentity(system, prefix) {
			return nil, false
		}
		identity := strconv.FormatUint(uint64(port.Index), 10)
		bindings = append(bindings, profile.ResourceBinding{Kind: "port", Identity: identity, RadioID: "", Prefixes: []string{prefix}})
	}
	return bindings, true
}

func uniqueRadioCapability(capabilities []profile.RadioCapability, band network.RadioBand) (profile.RadioCapability, bool) {
	var match profile.RadioCapability
	found := false
	for _, capability := range capabilities {
		if capability.Band != band {
			continue
		}
		if found || capability.ID == "" || capability.Interface == "" {
			return match, false
		}
		match = capability
		found = true
	}
	return match, found
}

func uniquePortCapability(capabilities []profile.PortCapability, index uint16) bool {
	count := 0
	for _, capability := range capabilities {
		if capability.Index == index {
			count++
		}
	}
	return count == 1
}

func uniqueRecordPrefix(values configmap.Values, namespace, suffix, expected string) (string, bool) {
	var prefixes []string
	for key, value := range values {
		if strings.HasPrefix(key, namespace) && strings.HasSuffix(key, suffix) && value == expected {
			prefixes = append(prefixes, strings.TrimSuffix(key, strings.TrimPrefix(suffix, ".")))
		}
	}
	return onlyPrefix(prefixes)
}

func matchingWirelessPrefixes(values configmap.Values, identity, parent string) []string {
	var prefixes []string
	for key, value := range values {
		if !strings.HasPrefix(key, "wireless.") || !strings.HasSuffix(key, ".ssid") || value != identity {
			continue
		}
		prefix := strings.TrimSuffix(key, "ssid")
		reportedParent, hasParent := values[prefix+"parent"]
		deviceName, hasDeviceName := values[prefix+"devname"]
		if hasParent && reportedParent == parent && hasDeviceName && deviceName != "" {
			prefixes = append(prefixes, prefix)
		}
	}
	return uniqueSorted(prefixes)
}

func matchingAAAPrefixes(values configmap.Values, identity, deviceName string) []string {
	var prefixes []string
	for key, value := range values {
		if !strings.HasPrefix(key, "aaa.") || !strings.HasSuffix(key, ".ssid") || value != identity {
			continue
		}
		prefix := strings.TrimSuffix(key, "ssid")
		reportedDeviceName, ok := values[prefix+"devname"]
		if deviceName != "" && ok && reportedDeviceName == deviceName {
			prefixes = append(prefixes, prefix)
		}
	}
	return uniqueSorted(prefixes)
}

func onlyPrefix(prefixes []string) (string, bool) {
	prefixes = uniqueSorted(prefixes)
	if len(prefixes) != 1 {
		return "", false
	}
	return prefixes[0], true
}

func uniqueSorted(values []string) []string {
	slices.Sort(values)
	return slices.Compact(values)
}

func hasSwitchPortIdentity(values configmap.Values, prefix string) bool {
	status, hasStatus := values[prefix+"status"]
	pvid, hasPVID := values[prefix+"pvid"]
	return values[prefix+"opmode"] == "switch" && hasStatus && status != "" && hasPVID && pvid != ""
}
