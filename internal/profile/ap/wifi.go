package ap

import (
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"goodkind.io/unifi-go/internal/configmap"
	"goodkind.io/unifi-go/internal/profile"
	"goodkind.io/unifi-go/network"
)

const (
	wifiResourceKind   = "wifi"
	wirelessMasterMode = "master"
	networksField      = "networks"
)

func copyWiFiProjection(
	prior network.APConfig,
	copies map[string]string,
) (network.APConfig, error) {
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

		if slices.ContainsFunc(
			result.Networks.Value,
			func(wifi network.WiFiNetwork) bool { return wifi.Name == destination },
		) {
			return network.APConfig{}, &network.ControlError{Code: network.BaselineUnusable}
		}

		index := slices.IndexFunc(
			prior.Networks.Value,
			func(wifi network.WiFiNetwork) bool { return wifi.Name == source },
		)
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

func resolveWiFi(
	values configmap.Values,
	name string,
	capability profile.RadioCapability,
) (profile.ResourceBinding, error) {
	var prefix string

	for _, candidate := range profile.RecordPrefixes(values, "wireless.") {
		if values[candidate+"ssid"] != name || values[candidate+"parent"] != capability.Interface {
			continue
		}

		if prefix != "" {
			return profile.ResourceBinding{}, &network.ControlError{Code: network.BaselineUnusable}
		}

		prefix = candidate
	}

	if prefix == "" || values[prefix+"devname"] == "" {
		return profile.ResourceBinding{}, &network.ControlError{Code: network.BaselineUnusable}
	}

	deviceName := values[prefix+"devname"]
	owner, err := profile.MatchRecord(values, "wireless.", "devname", deviceName)
	if err != nil || owner != prefix {
		return profile.ResourceBinding{}, &network.ControlError{Code: network.BaselineUnusable}
	}

	aaa, err := profile.MatchRecord(values, "aaa.", "devname", deviceName)
	if err != nil || aaa == "" || values[aaa+"ssid"] != name {
		return profile.ResourceBinding{}, &network.ControlError{Code: network.BaselineUnusable}
	}

	prefixes := []string{prefix, aaa}
	netconf, err := profile.MatchRecord(values, "netconf.", "devname", deviceName)
	if err != nil {
		slog.Warn("configuration composition failed")

		return profile.ResourceBinding{}, fmt.Errorf("resolve WLAN: %w", err)
	}

	if netconf != "" {
		prefixes = append(prefixes, netconf)
	}

	bridge, err := profile.MatchRecord(values, "bridge.", "devname", values[aaa+"br.devname"])
	if err != nil || bridge == "" {
		return profile.ResourceBinding{}, &network.ControlError{Code: network.BaselineUnusable}
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

	return profile.ResourceBinding{
		Kind:     wifiResourceKind,
		Identity: name,
		RadioID:  capability.ID,
		Prefixes: prefixes,
	}, nil
}

func wifiBinding(
	bindings []profile.ResourceBinding,
	name string,
	radioID string,
) (profile.ResourceBinding, bool) {
	for _, binding := range bindings {
		if binding.Kind == wifiResourceKind && binding.Identity == name &&
			binding.RadioID == radioID {
			return binding, true
		}
	}

	return profile.ResourceBinding{Kind: "", Identity: "", RadioID: "", Prefixes: nil}, false
}

func retainsWiFi(
	config network.APConfig,
	radios []resolvedRadio,
	binding profile.ResourceBinding,
) (bool, error) {
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

func overlayWiFi(
	values configmap.Values,
	descriptor profile.DeviceDescriptor,
	binding profile.ResourceBinding,
	wifi network.WiFiNetwork,
	secrets profile.SecretReader,
) error {
	wireless, aaa := binding.Prefixes[0], binding.Prefixes[1]
	if wifi.Enabled.Present {
		values[wireless+"status"], values[aaa+"status"] = enabled(wifi.Enabled.Value), enabled(
			wifi.Enabled.Value,
		)
	}

	if wifi.BSSTransition.Present {
		if err := values.Set(aaa+"bss_transition", string(wifi.BSSTransition.Value)); err != nil {
			slog.Warn("configuration composition failed")

			return fmt.Errorf("compose access point: %w", err)
		}
	}

	securityChanged := wifi.Security.Present &&
		(wifi.Security.Value.Mode.Present || wifi.Security.Value.PSK.Present)
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

func addWiFi(
	values configmap.Values,
	descriptor profile.DeviceDescriptor,
	bindings []profile.ResourceBinding,
	capability profile.RadioCapability,
	wifi network.WiFiNetwork,
	copyFrom string,
	secrets profile.SecretReader,
) (profile.ResourceBinding, error) {
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
		extra, err = copyWiFiRecords(
			values,
			*source,
			wireless,
			aaa,
			deviceName,
			capability.Interface,
		)
		if err != nil {
			return profile.ResourceBinding{}, err
		}
	} else {
		values[wireless+"mode"], values[wireless+"security"], values[wireless+"authmode"] = wirelessMasterMode, "none", "1"
		values[aaa+"driver"] = "madwifi"
	}

	values[wireless+"ssid"], values[aaa+"ssid"] = wifi.Name, wifi.Name
	values[wireless+"devname"] = deviceName
	values[aaa+"devname"] = deviceName
	values[wireless+"parent"] = capability.Interface
	radio, err := profile.MatchRecord(values, "radio.", "phyname", capability.Interface)
	if err != nil || radio == "" {
		return profile.ResourceBinding{}, &network.ControlError{Code: network.BaselineUnusable}
	}

	if values[radio+"devname"] == "" {
		values[radio+"devname"] = deviceName
	} else {
		virtual := profile.NextRecord(values, radio+"virtual.")
		values[virtual+"devname"] = deviceName
		values[virtual+"mode"] = wirelessMasterMode
		values[virtual+"status"] = string(boundRadioEnabled)
	}

	if len(extra) == 0 {
		netconf := profile.NextRecord(values, "netconf.")
		values[netconf+"devname"] = deviceName
		values[netconf+"status"] = string(boundRadioEnabled)
		values[netconf+"up"] = "disabled"
		extra = append(extra, netconf)
	}

	binding := profile.ResourceBinding{
		Kind:     wifiResourceKind,
		Identity: wifi.Name,
		RadioID:  capability.ID,
		Prefixes: append([]string{wireless, aaa}, extra...),
	}
	if source != nil {
		// The copied bridge reference needs a distinct member for the new interface.
		bridgeName := values[aaa+"br.devname"]
		bridge, err := profile.MatchRecord(values, "bridge.", "devname", bridgeName)
		if err != nil || bridge == "" {
			return profile.ResourceBinding{}, &network.ControlError{Code: network.BaselineUnusable}
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

func selectWiFiSource(
	bindings []profile.ResourceBinding,
	wifiName string,
	copyFrom string,
	radioID string,
) (*profile.ResourceBinding, error) {
	// Resource copies name their source. Band extensions copy only the same WLAN.
	sourceName := wifiName
	if copyFrom != "" {
		sourceName = copyFrom
	}

	var source *profile.ResourceBinding

	for index, binding := range bindings {
		if binding.Kind != wifiResourceKind || binding.Identity != sourceName {
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

func removeWiFiMembers(
	values configmap.Values,
	radios []resolvedRadio,
	bindings []profile.ResourceBinding,
	effective network.APConfig,
) error {
	for _, binding := range bindings {
		if binding.Kind != wifiResourceKind {
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

func requireWiFiPolicy(wifi network.WiFiNetwork) error {
	selectorPresent := wifi.Bands.Present || wifi.RadioIDs.Present
	if !wifi.Enabled.Present || !wifi.VLAN.Present || !selectorPresent ||
		!wifi.BSSTransition.Present ||
		!wifi.Security.Present ||
		!wifi.Security.Value.Mode.Present ||
		!wifi.Security.Value.PSK.Present {
		return &network.ControlError{Code: network.PolicyRequired, Field: networksField}
	}

	return nil
}

func copyWiFiRecords(
	values configmap.Values,
	source profile.ResourceBinding,
	wireless string,
	aaa string,
	deviceName string,
	parent string,
) ([]string, error) {
	oldDevice := values[source.Prefixes[0]+"devname"]
	oldParent := values[source.Prefixes[0]+"parent"]
	references := map[string]string{oldDevice: deviceName, oldParent: parent}
	profile.CopyBindingRecords(
		values,
		map[string]string{source.Prefixes[0]: wireless, source.Prefixes[1]: aaa},
		references,
	)
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

func refreshWiFiBinding(
	values configmap.Values,
	descriptor profile.DeviceDescriptor,
	binding profile.ResourceBinding,
) (profile.ResourceBinding, error) {
	for _, radio := range descriptor.Radios {
		if radio.ID == binding.RadioID {
			return resolveWiFi(values, binding.Identity, radio)
		}
	}

	return profile.ResourceBinding{
		Kind:     "",
		Identity: "",
		RadioID:  "",
		Prefixes: nil,
	}, &network.ControlError{
		Code:  network.BaselineUnusable,
		Field: "",
	}
}
