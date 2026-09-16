// Package ap compiles access point configuration from reported capabilities.
package ap

import (
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"

	"goodkind.io/unifi-go/internal/configmap"
	"goodkind.io/unifi-go/internal/profile"
	"goodkind.io/unifi-go/network"
)

type compiler struct{}

// New returns the capability-driven access point compiler.
func New() profile.APCompiler { return compiler{} }

func (compiler) Supports(descriptor profile.DeviceDescriptor) bool {
	return descriptor.Family == network.FamilyAP && descriptor.Protocol.PacketVersion <= 1 && descriptor.Protocol.PayloadVersion == 1 && descriptor.Protocol.SystemConfig && descriptor.Protocol.ManagementConfig
}

func (compiler) Compile(descriptor profile.DeviceDescriptor, input profile.CompilationInput, request network.APConfig, secrets profile.SecretReader) (profile.Compilation, error) {
	if !New().Supports(descriptor) {
		return profile.Compilation{}, fmt.Errorf("unsupported access point configuration protocol")
	}
	request = request.Clone()
	if err := request.Validate(); err != nil {
		slog.Warn("configuration composition failed")
		return profile.Compilation{}, fmt.Errorf("compose access point: %w", err)
	}
	if err := resolveConfigRadioIDs(descriptor, &request); err != nil {
		slog.Warn("configuration composition failed")
		return profile.Compilation{}, fmt.Errorf("compose access point: %w", err)
	}
	if input.Switch != nil {
		return profile.Compilation{}, &network.ControlError{Code: network.BaselineUnusable, Field: ""}
	}
	param, err := profile.CloneBaseline(input)
	if err != nil {
		slog.Warn("configuration composition failed")
		return profile.Compilation{}, fmt.Errorf("compose access point: %w", err)
	}
	prior := profile.MergeAP(input.AP, network.APConfig{})
	if err := resolveConfigRadioIDs(descriptor, &prior); err != nil {
		slog.Warn("configuration composition failed")
		return profile.Compilation{}, fmt.Errorf("compose access point: %w", err)
	}
	effective, err := mergeEffectiveConfig(prior, request, input.WiFiCopies)
	if err != nil {
		return profile.Compilation{}, err
	}
	radios, err := resolveCompilationRadios(descriptor, prior, &effective)
	if err != nil {
		slog.Warn("configuration composition failed")
		return profile.Compilation{}, fmt.Errorf("compose access point: %w", err)
	}
	bindings, err := resolveBindings(param.System, radios.PriorConfigured, radios.PriorAvailable, prior)
	if err != nil {
		slog.Warn("configuration composition failed")
		return profile.Compilation{}, fmt.Errorf("compose access point: %w", err)
	}
	if err := verifyBindings(input.Bindings, bindings); err != nil {
		slog.Warn("configuration composition failed")
		return profile.Compilation{}, fmt.Errorf("compose access point: %w", err)
	}
	if request.CountryCode.Present {
		param.System["radio.countrycode"] = strconv.Itoa(int(request.CountryCode.Value))
		for _, prefix := range profile.RecordPrefixes(param.System, "radio.") {
			param.System[prefix+"countrycode"] = strconv.Itoa(int(request.CountryCode.Value))
		}
	}
	for _, radio := range request.Radios.Value {
		if err := overlayRadio(param.System, descriptor, radios.EffectiveConfigured, radio, effective); err != nil {
			slog.Warn("configuration composition failed")
			return profile.Compilation{}, fmt.Errorf("compose access point: %w", err)
		}
	}
	if err := overlayNetworks(param.System, descriptor, radios.EffectiveAvailable, bindings, effective, request, input.WiFiCopies, secrets); err != nil {
		slog.Warn("configuration composition failed")
		return profile.Compilation{}, fmt.Errorf("compose access point: %w", err)
	}
	if err := removeMembers(param.System, radios.EffectiveAvailable, bindings, effective, request); err != nil {
		slog.Warn("configuration composition failed")
		return profile.Compilation{}, fmt.Errorf("compose access point: %w", err)
	}
	if request.SSH.Present {
		if err := profile.WriteSSH(param.System, request.SSH.Value, secrets); err != nil {
			slog.Warn("configuration composition failed")
			return profile.Compilation{}, fmt.Errorf("compose access point: %w", err)
		}
	}
	bindings, err = resolveBindings(param.System, radios.EffectiveConfigured, radios.EffectiveAvailable, effective)
	if err != nil {
		slog.Warn("configuration composition failed")
		return profile.Compilation{}, fmt.Errorf("compose access point: %w", err)
	}
	param.Version, err = profile.CanonicalVersion(param)
	if err != nil {
		slog.Warn("configuration composition failed")
		return profile.Compilation{}, fmt.Errorf("compose access point: %w", err)
	}
	return profile.Compilation{Param: param, AP: &effective, Switch: nil, Bindings: profile.CloneBindings(bindings)}, nil
}

func mergeEffectiveConfig(prior, request network.APConfig, copies map[string]string) (network.APConfig, error) {
	effectivePrior, err := copyWiFiProjection(prior, copies)
	if err != nil {
		slog.Warn("configuration composition failed")
		return network.APConfig{}, fmt.Errorf("compose access point: %w", err)
	}
	effective := profile.MergeAP(&effectivePrior, request)
	if err := effective.Validate(); err != nil {
		slog.Warn("configuration composition failed")
		return network.APConfig{}, fmt.Errorf("compose access point: %w", err)
	}
	return effective, nil
}

func copyWiFiProjection(prior network.APConfig, copies map[string]string) (network.APConfig, error) {
	result := prior.Clone()
	destinations := make([]string, 0, len(copies))
	for destination := range copies {
		destinations = append(destinations, destination)
	}
	slices.Sort(destinations)
	for _, destination := range destinations {
		source := copies[destination]
		if destination == source {
			continue
		}
		if slices.ContainsFunc(result.Networks.Value, func(wifi network.WiFiNetwork) bool { return wifi.Name == destination }) {
			return network.APConfig{}, &network.ControlError{Code: network.BaselineUnusable}
		}
		index := slices.IndexFunc(prior.Networks.Value, func(wifi network.WiFiNetwork) bool { return wifi.Name == source })
		if index < 0 {
			return network.APConfig{}, &network.ControlError{Code: network.BaselineUnusable}
		}
		wifi := cloneWiFi(prior.Networks.Value[index])
		wifi.Name = destination
		result.Networks.Value = append(result.Networks.Value, wifi)
	}
	return result, nil
}

func cloneWiFi(wifi network.WiFiNetwork) network.WiFiNetwork {
	config := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{wifi})}.Clone()
	return config.Networks.Value[0]
}

func resolveConfigRadioIDs(descriptor profile.DeviceDescriptor, config *network.APConfig) error {
	if !config.Radios.Present {
		return nil
	}
	resolved, err := resolveRadios(descriptor, config.Radios.Value)
	if err != nil {
		return err
	}
	for index := range resolved {
		config.Radios.Value[index] = resolved[index].Config
	}
	return nil
}

func resolveBindings(values configmap.Values, configuredRadios, availableRadios []resolvedRadio, config network.APConfig) ([]profile.ResourceBinding, error) {
	var result []profile.ResourceBinding
	for _, radio := range configuredRadios {
		capability := radio.Capability
		prefix, err := profile.MatchRecord(values, "radio.", "phyname", capability.Interface)
		if err != nil || prefix == "" {
			return nil, &network.ControlError{Code: network.BaselineUnusable, Field: ""}
		}
		result = append(result, profile.ResourceBinding{Kind: "radio", Identity: string(radio.Config.ID), RadioID: capability.ID, Prefixes: []string{prefix}})
	}
	for _, wifi := range config.Networks.Value {
		selected, err := resolveNetworkRadios(wifi, availableRadios)
		if err != nil {
			return nil, fmt.Errorf("resolve access point: %w", err)
		}
		for _, radio := range selected {
			binding, err := resolveWiFi(values, wifi.Name, radio.Capability)
			if err != nil {
				slog.Warn("configuration composition failed")
				return nil, fmt.Errorf("resolve access point: %w", err)
			}
			result = append(result, binding)
		}
	}
	result = profile.CloneBindings(result)
	for index := 1; index < len(result); index++ {
		prior, current := result[index-1], result[index]
		if prior.Kind == current.Kind && prior.Identity == current.Identity && prior.RadioID == current.RadioID {
			return nil, &network.ControlError{Code: network.BaselineUnusable, Field: ""}
		}
	}
	return result, nil
}

func resolveWiFi(values configmap.Values, name string, capability profile.RadioCapability) (profile.ResourceBinding, error) {
	var prefix string
	for _, candidate := range profile.RecordPrefixes(values, "wireless.") {
		if values[candidate+"ssid"] != name || values[candidate+"parent"] != capability.Interface {
			continue
		}
		if prefix != "" {
			return profile.ResourceBinding{Kind: "", Identity: "", RadioID: "", Prefixes: nil}, &network.ControlError{Code: network.BaselineUnusable, Field: ""}
		}
		prefix = candidate
	}
	if prefix == "" || values[prefix+"devname"] == "" {
		return profile.ResourceBinding{Kind: "", Identity: "", RadioID: "", Prefixes: nil}, &network.ControlError{Code: network.BaselineUnusable, Field: ""}
	}
	deviceName := values[prefix+"devname"]
	owner, err := profile.MatchRecord(values, "wireless.", "devname", deviceName)
	if err != nil || owner != prefix {
		return profile.ResourceBinding{}, &network.ControlError{Code: network.BaselineUnusable}
	}
	aaa, err := profile.MatchRecord(values, "aaa.", "devname", deviceName)
	if err != nil || aaa == "" || values[aaa+"ssid"] != name {
		return profile.ResourceBinding{Kind: "", Identity: "", RadioID: "", Prefixes: nil}, &network.ControlError{Code: network.BaselineUnusable, Field: ""}
	}
	prefixes := []string{prefix, aaa}
	netconf, err := profile.MatchRecord(values, "netconf.", "devname", deviceName)
	if err != nil {
		slog.Warn("configuration composition failed")
		return profile.ResourceBinding{Kind: "", Identity: "", RadioID: "", Prefixes: nil}, fmt.Errorf("resolve WLAN: %w", err)
	}
	if netconf != "" {
		prefixes = append(prefixes, netconf)
	}
	bridge, err := profile.MatchRecord(values, "bridge.", "devname", values[aaa+"br.devname"])
	if err != nil || bridge == "" {
		return profile.ResourceBinding{Kind: "", Identity: "", RadioID: "", Prefixes: nil}, &network.ControlError{Code: network.BaselineUnusable, Field: ""}
	}
	member, err := uniqueBridgeMember(values, deviceName)
	if err != nil || member != "" && !strings.HasPrefix(member, bridge+"port.") {
		return profile.ResourceBinding{}, &network.ControlError{Code: network.BaselineUnusable}
	}
	if member != "" {
		prefixes = append(prefixes, member)
	}
	filters, err := interfaceFilters(values, deviceName)
	if err != nil {
		return profile.ResourceBinding{}, err
	}
	prefixes = append(prefixes, filters...)
	return profile.ResourceBinding{Kind: "wifi", Identity: name, RadioID: capability.ID, Prefixes: prefixes}, nil
}

func interfaceFilters(values configmap.Values, deviceName string) ([]string, error) {
	wirelessDevices := make(map[string]bool)
	for _, prefix := range profile.RecordPrefixes(values, "wireless.") {
		wirelessDevices[values[prefix+"devname"]] = true
	}
	var result []string
	for _, command := range profile.RecordPrefixes(values, "ebtables.") {
		references, err := filterInterfaceReferences(values[command+"cmd"])
		if err != nil {
			return nil, err
		}
		interfaces := make(map[string]bool)
		for _, reference := range references {
			if wirelessDevices[reference.name] {
				interfaces[reference.name] = true
			}
		}
		if !interfaces[deviceName] {
			continue
		}
		if len(interfaces) != 1 {
			return nil, &network.ControlError{Code: network.BaselineUnusable}
		}
		result = append(result, command)
	}
	return result, nil
}

func verifyBindings(stored, resolved []profile.ResourceBinding) error {
	for _, binding := range stored {
		if bindingIndex(binding, resolved) < 0 {
			return &network.ControlError{Code: network.BaselineUnusable, Field: ""}
		}
	}
	return nil
}

func bindingIndex(binding profile.ResourceBinding, resolved []profile.ResourceBinding) int {
	if len(binding.Prefixes) == 0 {
		return -1
	}
	stableIndex := slices.IndexFunc(resolved, func(candidate profile.ResourceBinding) bool {
		return candidate.Kind == binding.Kind && candidate.Identity == binding.Identity && candidate.RadioID == binding.RadioID && includesPrefixes(candidate, binding)
	})
	if stableIndex >= 0 {
		return stableIndex
	}
	if !legacyRadioID(binding.RadioID) {
		return -1
	}
	legacyIndex := -1
	for candidateIndex, candidate := range resolved {
		identityMatches := binding.Kind == "radio" || candidate.Identity == binding.Identity
		if candidate.Kind != binding.Kind || !identityMatches || !includesPrefixes(candidate, binding) {
			continue
		}
		if legacyIndex >= 0 {
			return -1
		}
		legacyIndex = candidateIndex
	}
	return legacyIndex
}

func legacyRadioID(identifier string) bool {
	switch reportedRadio(identifier) {
	case reportedRadioNG, reportedRadio2G, reportedRadio24G, reportedRadioNA, reportedRadio5G, reportedRadio5GHz:
		return true
	default:
		return false
	}
}

func includesPrefixes(candidate, stored profile.ResourceBinding) bool {
	for _, prefix := range stored.Prefixes {
		if !slices.Contains(candidate.Prefixes, prefix) {
			return false
		}
	}
	return true
}

func wifiBinding(bindings []profile.ResourceBinding, name, radioID string) (profile.ResourceBinding, bool) {
	for _, binding := range bindings {
		if binding.Kind == "wifi" && binding.Identity == name && binding.RadioID == radioID {
			return binding, true
		}
	}
	return profile.ResourceBinding{Kind: "", Identity: "", RadioID: "", Prefixes: nil}, false
}

func retainsWiFi(config network.APConfig, radios []resolvedRadio, binding profile.ResourceBinding) (bool, error) {
	for _, wifi := range config.Networks.Value {
		if wifi.Name != binding.Identity {
			continue
		}
		selected, err := resolveNetworkRadios(wifi, radios)
		if err != nil {
			return false, err
		}
		for _, radio := range selected {
			if radio.Capability.ID == binding.RadioID {
				return true, nil
			}
		}
	}
	return false, nil
}

func removeWiFi(values configmap.Values, binding profile.ResourceBinding) error {
	deviceName := values[binding.Prefixes[0]+"devname"]
	bridgeName := values[binding.Prefixes[1]+"br.devname"]
	parent := values[binding.Prefixes[0]+"parent"]
	for _, prefix := range binding.Prefixes {
		profile.DeleteRecord(values, prefix)
	}
	radio, err := profile.MatchRecord(values, "radio.", "phyname", parent)
	if err != nil {
		slog.Warn("configuration composition failed")
		return fmt.Errorf("compose access point: %w", err)
	}
	if radio != "" {
		removeRadioInterface(values, radio, parent, deviceName)
	}
	return removeUnusedBridge(values, bridgeName)
}

func removeUnusedBridge(values configmap.Values, name string) error {
	if name == "" || name == "br0" {
		return nil
	}
	for _, prefix := range profile.RecordPrefixes(values, "aaa.") {
		if values[prefix+"br.devname"] == name {
			return nil
		}
	}
	bridge, err := profile.MatchRecord(values, "bridge.", "devname", name)
	if err != nil {
		slog.Warn("configuration composition failed")
		return fmt.Errorf("resolve bridge: %w", err)
	}
	if bridge == "" {
		return nil
	}
	members := profile.RecordPrefixes(values, bridge+"port.")
	// An unrecognized interface keeps its bridge; only known VLAN dependencies can be collected.
	for _, member := range members {
		if vlanInterface(values, values[member+"devname"]) == "" {
			return nil
		}
	}
	for _, member := range members {
		deviceName := values[member+"devname"]
		if usedByOtherBridge(values, bridge, deviceName) {
			continue
		}
		profile.DeleteRecord(values, vlanInterface(values, deviceName))
		if err := removeNetconf(values, deviceName); err != nil {
			return err
		}
	}
	profile.DeleteRecord(values, bridge)
	return removeNetconf(values, name)
}

func removeNetconf(values configmap.Values, deviceName string) error {
	prefix, err := profile.MatchRecord(values, "netconf.", "devname", deviceName)
	if err != nil {
		slog.Warn("configuration composition failed")
		return fmt.Errorf("remove interface: %w", err)
	}
	if prefix != "" {
		profile.DeleteRecord(values, prefix)
	}
	return nil
}

func vlanInterface(values configmap.Values, deviceName string) string {
	for _, prefix := range profile.RecordPrefixes(values, "vlan.") {
		if values[prefix+"devname"]+"."+values[prefix+"id"] == deviceName {
			return prefix
		}
	}
	return ""
}

func usedByOtherBridge(values configmap.Values, excluded, deviceName string) bool {
	for _, bridge := range profile.RecordPrefixes(values, "bridge.") {
		if bridge == excluded {
			continue
		}
		for _, member := range profile.RecordPrefixes(values, bridge+"port.") {
			if values[member+"devname"] == deviceName {
				return true
			}
		}
	}
	return false
}

func overlayRadio(values configmap.Values, descriptor profile.DeviceDescriptor, radios []resolvedRadio, request network.RadioConfig, effective network.APConfig) error {
	selectedRadio, err := resolveRequestedRadio(request, radios)
	if err != nil {
		slog.Warn("configuration composition failed")
		return fmt.Errorf("compose access point: %w", err)
	}
	capability := selectedRadio.Capability
	prefix, err := profile.MatchRecord(values, "radio.", "phyname", capability.Interface)
	if err != nil {
		slog.Warn("configuration composition failed")
		return fmt.Errorf("compose access point: %w", err)
	}
	if prefix == "" {
		return &network.ControlError{Code: network.PolicyRequired, Field: "radios"}
	}
	var effectiveRadio network.RadioConfig
	for _, radio := range effective.Radios.Value {
		if radio.ID == selectedRadio.Config.ID {
			effectiveRadio = radio
		}
	}
	effectiveRadio = resolveBoundRadio(values, prefix, effectiveRadio)
	if err := (network.APConfig{Radios: network.Supplied([]network.RadioConfig{effectiveRadio})}).Validate(); err != nil {
		return fmt.Errorf("validate resolved radio: %w", err)
	}
	exception := effectiveRadio.Channel.Present && effectiveRadio.WidthMHz.Present && reproducedRadioSetting(descriptor, effectiveRadio)
	if request.Channel.Present && !request.Channel.Null && !slices.Contains(capability.Channels, request.Channel.Value) && (len(capability.Channels) != 0 || !exception) {
		return fmt.Errorf("radios: requested channel lacks capability evidence")
	}
	if request.WidthMHz.Present && !slices.Contains(capability.Widths, request.WidthMHz.Value) && (len(capability.Widths) != 0 || !exception) {
		return fmt.Errorf("radios: requested width lacks capability evidence")
	}
	if request.Enabled.Present {
		values[prefix+"status"] = enabled(request.Enabled.Value)
	}
	if request.Channel.Present {
		channel := "auto"
		if !request.Channel.Null {
			channel = strconv.Itoa(int(request.Channel.Value))
		}
		values[prefix+"channel"] = channel
	}
	if request.WidthMHz.Present {
		values[prefix+"cwm.mode"] = widthMode(request.Band, request.WidthMHz.Value)
		values[prefix+"ieee_mode"] = ieeeMode(request.Band, request.WidthMHz.Value)
	}
	if request.Power.Present {
		return overlayPower(values, prefix, capability, effectiveRadio, request)
	}
	return nil
}

func overlayWiFi(values configmap.Values, descriptor profile.DeviceDescriptor, binding profile.ResourceBinding, wifi network.WiFiNetwork, secrets profile.SecretReader) error {
	wireless, aaa := binding.Prefixes[0], binding.Prefixes[1]
	if wifi.Enabled.Present {
		values[wireless+"status"], values[aaa+"status"] = enabled(wifi.Enabled.Value), enabled(wifi.Enabled.Value)
	}
	if wifi.BSSTransition.Present {
		if err := values.Set(aaa+"bss_transition", string(wifi.BSSTransition.Value)); err != nil {
			slog.Warn("configuration composition failed")
			return fmt.Errorf("compose access point: %w", err)
		}
	}
	securityChanged := wifi.Security.Present && (wifi.Security.Value.Mode.Present || wifi.Security.Value.PSK.Present)
	if securityChanged {
		if err := overlaySecurity(values, wireless, aaa, wifi.Security.Value, secrets); err != nil {
			return err
		}
		if err := validateEffectiveSecurity(values, aaa); err != nil {
			return err
		}
	}
	if wifi.VLAN.Present {
		return assignBridge(values, descriptor, wireless, aaa, wifi.VLAN)
	}
	return nil
}

func assignBridge(values configmap.Values, descriptor profile.DeviceDescriptor, wireless, aaa string, vlan network.Optional[network.VLANID]) error {
	name := "br0"
	if !vlan.Null {
		name = fmt.Sprintf("br0.%d", vlan.Value)
	}
	oldName := values[aaa+"br.devname"]
	if oldName == name {
		return nil
	}
	deviceName := values[wireless+"devname"]
	bridge, err := profile.MatchRecord(values, "bridge.", "devname", name)
	if err != nil {
		slog.Warn("configuration composition failed")
		return fmt.Errorf("compose access point: %w", err)
	}
	if bridge == "" {
		if vlan.Null {
			return &network.ControlError{Code: network.BaselineUnusable, Field: ""}
		}
		bridge = profile.NextRecord(values, "bridge.")
		values[bridge+"devname"] = name
		netconf := profile.NextRecord(values, "netconf.")
		values[netconf+"devname"], values[netconf+"status"], values[netconf+"up"] = name, "enabled", "enabled"
		for _, port := range descriptor.Ports {
			if port.Interface == "" {
				continue
			}
			wireName := fmt.Sprintf("%s.%d", port.Interface, vlan.Value)
			prefix := profile.NextRecord(values, "vlan.")
			values[prefix+"devname"], values[prefix+"id"] = port.Interface, strconv.Itoa(int(vlan.Value))
			member := profile.NextRecord(values, bridge+"port.")
			values[member+"devname"] = wireName
			netconf := profile.NextRecord(values, "netconf.")
			values[netconf+"devname"], values[netconf+"status"], values[netconf+"up"] = wireName, "enabled", "enabled"
		}
	}
	source, err := uniqueBridgeMember(values, deviceName)
	if err != nil {
		return err
	}
	member := profile.NextRecord(values, bridge+"port.")
	if source != "" {
		profile.CopyBindingRecords(values, map[string]string{source: member}, nil)
		profile.DeleteRecord(values, source)
	}
	values[member+"devname"] = deviceName
	values[aaa+"br.devname"] = name
	return removeUnusedBridge(values, oldName)
}

func addWiFi(values configmap.Values, descriptor profile.DeviceDescriptor, bindings []profile.ResourceBinding, capability profile.RadioCapability, wifi network.WiFiNetwork, copyFrom string, secrets profile.SecretReader) (profile.ResourceBinding, error) {
	source, err := selectWiFiSource(bindings, wifi.Name, copyFrom, capability.ID)
	if err != nil {
		return profile.ResourceBinding{}, err
	}
	if source == nil {
		if err := requireWiFiPolicy(wifi); err != nil {
			return profile.ResourceBinding{Kind: "", Identity: "", RadioID: "", Prefixes: nil}, err
		}
	} else {
		refreshed, err := refreshWiFiBinding(values, descriptor, *source)
		if err != nil {
			return profile.ResourceBinding{Kind: "", Identity: "", RadioID: "", Prefixes: nil}, err
		}
		source = &refreshed
	}
	wireless, aaa := profile.NextRecord(values, "wireless."), profile.NextRecord(values, "aaa.")
	deviceName := availableInterface(values, capability.Interface)
	var extra []string
	if source != nil {
		var err error
		extra, err = copyWiFiRecords(values, *source, wireless, aaa, deviceName, capability.Interface)
		if err != nil {
			return profile.ResourceBinding{}, err
		}
	} else {
		values[wireless+"mode"], values[wireless+"security"], values[wireless+"authmode"] = "master", "none", "1"
		values[aaa+"driver"] = "madwifi"
	}
	values[wireless+"ssid"], values[aaa+"ssid"] = wifi.Name, wifi.Name
	values[wireless+"devname"], values[aaa+"devname"], values[wireless+"parent"] = deviceName, deviceName, capability.Interface
	radio, err := profile.MatchRecord(values, "radio.", "phyname", capability.Interface)
	if err != nil || radio == "" {
		return profile.ResourceBinding{Kind: "", Identity: "", RadioID: "", Prefixes: nil}, &network.ControlError{Code: network.BaselineUnusable, Field: ""}
	}
	if values[radio+"devname"] == "" {
		values[radio+"devname"] = deviceName
	} else {
		virtual := profile.NextRecord(values, radio+"virtual.")
		values[virtual+"devname"], values[virtual+"mode"], values[virtual+"status"] = deviceName, "master", "enabled"
	}
	if len(extra) == 0 {
		netconf := profile.NextRecord(values, "netconf.")
		values[netconf+"devname"], values[netconf+"status"], values[netconf+"up"] = deviceName, "enabled", "disabled"
		extra = append(extra, netconf)
	}
	binding := profile.ResourceBinding{Kind: "wifi", Identity: wifi.Name, RadioID: capability.ID, Prefixes: append([]string{wireless, aaa}, extra...)}
	if source != nil {
		// The copied bridge reference needs a distinct member for the new interface.
		bridgeName := values[aaa+"br.devname"]
		bridge, err := profile.MatchRecord(values, "bridge.", "devname", bridgeName)
		if err != nil || bridge == "" {
			return profile.ResourceBinding{Kind: "", Identity: "", RadioID: "", Prefixes: nil}, &network.ControlError{Code: network.BaselineUnusable, Field: ""}
		}
		if !hasBridgeMember(values, bridge, deviceName) {
			member := profile.NextRecord(values, bridge+"port.")
			values[member+"devname"] = deviceName
		}
	} else if err := overlayWiFi(values, descriptor, binding, wifi, secrets); err != nil {
		return binding, err
	}
	return binding, nil
}

func selectWiFiSource(bindings []profile.ResourceBinding, wifiName, copyFrom, radioID string) (*profile.ResourceBinding, error) {
	// Resource copies name their source. Band extensions copy only the same WLAN.
	sourceName := wifiName
	if copyFrom != "" {
		sourceName = copyFrom
	}
	var source *profile.ResourceBinding
	for index, binding := range bindings {
		if binding.Kind != "wifi" || binding.Identity != sourceName {
			continue
		}
		if copyFrom != "" && binding.RadioID != radioID {
			continue
		}
		if source != nil {
			return nil, &network.ControlError{Code: network.BaselineUnusable}
		}
		source = &bindings[index]
	}
	if copyFrom != "" && source == nil {
		return nil, &network.ControlError{Code: network.BaselineUnusable}
	}
	return source, nil
}

func ieeeMode(band network.RadioBand, width network.ChannelWidthMHz) string {
	if band == network.Band2GHz {
		return fmt.Sprintf("11nght%d", width)
	}
	return fmt.Sprintf("11naht%d", width)
}

func widthMode(band network.RadioBand, width network.ChannelWidthMHz) string {
	if band == network.Band2GHz && width == network.Width40 {
		return "1"
	}
	return "0"
}

func enabled(value bool) string {
	if value {
		return "enabled"
	}
	return "disabled"
}

func virtualInterface(physicalInterface string, globalVAPIndex int) string {
	suffix := strings.TrimPrefix(physicalInterface, "wifi")
	if suffix != physicalInterface && suffix != "" {
		if _, err := strconv.ParseUint(suffix, 10, 32); err == nil {
			return fmt.Sprintf("%sap%d", physicalInterface, globalVAPIndex)
		}
	}
	return fmt.Sprintf("ath%d", globalVAPIndex)
}

func removeMembers(values configmap.Values, radios []resolvedRadio, bindings []profile.ResourceBinding, effective, request network.APConfig) error {
	if request.Networks.Present {
		if err := removeWiFiMembers(values, radios, bindings, effective); err != nil {
			return err
		}
	}
	return removeRadios(values, bindings, effective, request)
}

func removeWiFiMembers(values configmap.Values, radios []resolvedRadio, bindings []profile.ResourceBinding, effective network.APConfig) error {
	for _, binding := range bindings {
		if binding.Kind != "wifi" {
			continue
		}
		retained, err := retainsWiFi(effective, radios, binding)
		if err != nil {
			return err
		}
		if retained {
			continue
		}
		if err := removeWiFi(values, binding); err != nil {
			slog.Warn("configuration composition failed")
			return fmt.Errorf("compose access point: %w", err)
		}
	}
	return nil
}

func overlayNetworks(values configmap.Values, descriptor profile.DeviceDescriptor, radios []resolvedRadio, bindings []profile.ResourceBinding, effective, request network.APConfig, copies map[string]string, secrets profile.SecretReader) error {
	networks := slices.Clone(request.Networks.Value)
	slices.SortFunc(networks, func(left, right network.WiFiNetwork) int { return strings.Compare(left.Name, right.Name) })
	for _, wifi := range networks {
		resolved := effective.Networks.Value[slices.IndexFunc(effective.Networks.Value, func(candidate network.WiFiNetwork) bool { return candidate.Name == wifi.Name })]
		selected, err := resolveNetworkRadios(resolved, radios)
		if err != nil {
			return err
		}
		for _, radio := range selected {
			capability := radio.Capability
			binding, found := wifiBinding(bindings, wifi.Name, capability.ID)
			if !found {
				binding, err = addWiFi(values, descriptor, bindings, capability, resolved, copies[wifi.Name], secrets)
				if err != nil {
					slog.Warn("configuration composition failed")
					return fmt.Errorf("compose access point: %w", err)
				}
			}
			if err := overlayWiFi(values, descriptor, binding, wifi, secrets); err != nil {
				slog.Warn("configuration composition failed")
				return fmt.Errorf("compose access point: %w", err)
			}
		}
	}

	return nil
}

func removeRadioInterface(values configmap.Values, radio, parent, deviceName string) {
	for _, prefix := range profile.RecordPrefixes(values, radio+"virtual.") {
		if values[prefix+"devname"] == deviceName {
			profile.DeleteRecord(values, prefix)
		}
	}
	if values[radio+"devname"] != deviceName {
		return
	}
	delete(values, radio+"devname")
	for _, prefix := range profile.RecordPrefixes(values, "wireless.") {
		if values[prefix+"parent"] != parent {
			continue
		}
		replacement := values[prefix+"devname"]
		values[radio+"devname"] = replacement
		return
	}
}

func overlayPower(values configmap.Values, prefix string, capability profile.RadioCapability, resolved, request network.RadioConfig) error {
	power := resolved.Power.Value
	if !power.Mode.Present {
		return &network.ControlError{Code: network.PolicyRequired, Field: "radios"}
	}
	if power.Mode.Value == network.PowerExplicit {
		if !power.DBm.Present {
			return &network.ControlError{Code: network.PolicyRequired, Field: "radios"}
		}
		if capability.MinPowerDBm == nil || capability.MaxPowerDBm == nil || power.DBm.Value < *capability.MinPowerDBm || power.DBm.Value > *capability.MaxPowerDBm {
			return fmt.Errorf("radios: requested power lacks capability evidence")
		}
		values[prefix+"txpower_mode"], values[prefix+"txpower"] = "custom", strconv.Itoa(power.DBm.Value)
	} else if request.Power.Value.Mode.Present {
		values[prefix+"txpower_mode"], values[prefix+"txpower"] = "auto", "auto"
	}
	return nil
}

func requireWiFiPolicy(wifi network.WiFiNetwork) error {
	selectorPresent := wifi.Bands.Present || wifi.RadioIDs.Present
	if !wifi.Enabled.Present || !wifi.VLAN.Present || !selectorPresent || !wifi.BSSTransition.Present || !wifi.Security.Present || !wifi.Security.Value.Mode.Present || !wifi.Security.Value.PSK.Present {
		return &network.ControlError{Code: network.PolicyRequired, Field: "networks"}
	}
	return nil
}

func availableInterface(values configmap.Values, physical string) string {
	for index := 0; ; index++ {
		candidate := virtualInterface(physical, index)
		used := false
		for key, value := range values {
			if strings.HasSuffix(key, ".devname") && value == candidate {
				used = true
				break
			}
		}
		if !used {
			return candidate
		}
	}
}

func hasBridgeMember(values configmap.Values, bridge, deviceName string) bool {
	for _, member := range profile.RecordPrefixes(values, bridge+"port.") {
		if values[member+"devname"] == deviceName {
			return true
		}
	}
	return false
}

func uniqueBridgeMember(values configmap.Values, deviceName string) (string, error) {
	var result string
	for _, bridge := range profile.RecordPrefixes(values, "bridge.") {
		for _, member := range profile.RecordPrefixes(values, bridge+"port.") {
			if values[member+"devname"] != deviceName {
				continue
			}
			if result != "" {
				return "", &network.ControlError{Code: network.BaselineUnusable, Field: ""}
			}
			result = member
		}
	}
	return result, nil
}

func copyWiFiRecords(values configmap.Values, source profile.ResourceBinding, wireless, aaa, deviceName, parent string) ([]string, error) {
	oldDevice := values[source.Prefixes[0]+"devname"]
	oldParent := values[source.Prefixes[0]+"parent"]
	references := map[string]string{oldDevice: deviceName, oldParent: parent}
	profile.CopyBindingRecords(values, map[string]string{source.Prefixes[0]: wireless, source.Prefixes[1]: aaa}, references)
	var extra []string
	for _, prefix := range source.Prefixes[2:] {
		namespace := "netconf."
		switch {
		case strings.HasPrefix(prefix, "bridge."):
			head, _, _ := strings.Cut(prefix, "port.")
			namespace = head + "port."
		case strings.HasPrefix(prefix, "ebtables."):
			namespace = "ebtables."
		}
		target := profile.NextRecord(values, namespace)
		profile.CopyBindingRecords(values, map[string]string{prefix: target}, references)
		if namespace == "ebtables." {
			command, err := rewriteFilterInterface(values[target+"cmd"], oldDevice, deviceName)
			if err != nil {
				return nil, err
			}
			values[target+"cmd"] = command
		}
		if namespace == "netconf." {
			extra = append(extra, target)
		}
	}
	return extra, nil
}

// This compatibility evidence is limited to reproduced settings on this firmware.
// Model identity never admits a device or supplies power bounds.
func reproducedRadioSetting(descriptor profile.DeviceDescriptor, requested network.RadioConfig) bool {
	if descriptor.Model != "U7PG2" || descriptor.Firmware != "6.8.2.15592" {
		return false
	}
	channel := uint16(0)
	if !requested.Channel.Null {
		channel = requested.Channel.Value
	}
	switch requested.Band {
	case network.Band2GHz:
		if requested.WidthMHz.Value == network.Width20 {
			return channel == 0 || channel == 6 || channel == 11
		}
		return requested.WidthMHz.Value == network.Width40 && channel == 6
	case network.Band5GHz:
		return requested.WidthMHz.Value == network.Width40 && (channel == 0 || channel == 44 || channel == 157)
	default:
		return false
	}
}

func removeRadios(values configmap.Values, bindings []profile.ResourceBinding, effective, request network.APConfig) error {
	if !request.Radios.Present {
		return nil
	}
	for _, binding := range bindings {
		if binding.Kind != "radio" {
			continue
		}
		if slices.ContainsFunc(effective.Radios.Value, func(radio network.RadioConfig) bool { return string(radio.ID) == binding.Identity }) {
			continue
		}
		if radioHasWireless(values, binding.Prefixes[0]) {
			return fmt.Errorf("radios: removed radio still has a WLAN")
		}
		for _, wifi := range effective.Networks.Value {
			if slices.Contains(wifi.RadioIDs.Value, network.RadioID(binding.Identity)) {
				return fmt.Errorf("radios: removed radio still has a WLAN")
			}
		}
		profile.DeleteRecord(values, binding.Prefixes[0])
	}

	return nil
}

func radioHasWireless(values configmap.Values, radioPrefix string) bool {
	parent := values[radioPrefix+"phyname"]
	for _, prefix := range profile.RecordPrefixes(values, "wireless.") {
		if values[prefix+"parent"] == parent {
			return true
		}
	}
	return false
}

func refreshWiFiBinding(values configmap.Values, descriptor profile.DeviceDescriptor, binding profile.ResourceBinding) (profile.ResourceBinding, error) {
	for _, radio := range descriptor.Radios {
		if radio.ID == binding.RadioID {
			return resolveWiFi(values, binding.Identity, radio)
		}
	}
	return profile.ResourceBinding{Kind: "", Identity: "", RadioID: "", Prefixes: nil}, &network.ControlError{Code: network.BaselineUnusable, Field: ""}
}
