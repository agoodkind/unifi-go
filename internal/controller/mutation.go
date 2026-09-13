package controller

import (
	"slices"
	"sort"
	"strconv"
	"strings"

	"goodkind.io/unifi-go/internal/configmap"
	"goodkind.io/unifi-go/internal/profile"
	"goodkind.io/unifi-go/network"
)

type desiredMutation func(*Device) *network.ControlError

func (c *Controller) mutateDesired(id network.DeviceID, family network.DeviceFamily, mutation desiredMutation) (network.ConfigVersion, error) {
	mac, err := normalizeMAC(string(id))
	if err != nil {
		return "", &network.ControlError{Code: network.InvalidDevice}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	device, exists := c.devices[mac]
	if !exists {
		return "", &network.ControlError{Code: network.NotRegistered}
	}
	if device.Family != family {
		return "", &network.ControlError{Code: network.FamilyMismatch}
	}
	report, exists := c.reports[mac]
	if !exists {
		return "", &network.ControlError{Code: network.NoReport}
	}
	if device.Baseline == nil {
		return "", &network.ControlError{Code: network.BaselineRequired}
	}
	if !device.Baseline.TypedReady || device.Baseline.SchemaVersion != baselineSchemaVersion {
		return "", &network.ControlError{Code: network.BaselineUnusable}
	}
	if !hasDesiredFamily(device, family) {
		return "", &network.ControlError{Code: network.DesiredStateMissing}
	}
	if c.awaiting[mac] != "" || len(c.queues[mac]) != 0 {
		return "", &network.ControlError{Code: network.ConfigurationPending}
	}
	if report.ConfigVersion != string(device.DesiredVersion) {
		return "", &network.ControlError{Code: network.ConfigurationDrift}
	}
	candidate := cloneMutationDevice(device)
	if failure := mutation(&candidate); failure != nil {
		return "", failure
	}
	descriptor, err := profile.DescribeWithFamily(report, family)
	if err != nil {
		return "", &network.ControlError{Code: network.FamilyMismatch}
	}
	sortDesiredResources(&candidate, descriptor)
	updatedAP, updatedSwitch := candidate.DesiredAP, candidate.DesiredSwitch
	candidate.DesiredAP, candidate.DesiredSwitch = cloneAP(device.DesiredAP), cloneSwitch(device.DesiredSwitch)
	compilation, err := c.compileLocked(candidate, family, updatedAP, updatedSwitch)
	if err != nil {
		return "", err
	}
	candidate.wifiCopies = nil
	return c.commitCompiledLocked(candidate, compilation)
}

func hasDesiredFamily(device Device, family network.DeviceFamily) bool {
	if device.DesiredVersion == "" {
		return false
	}
	if family == network.FamilyAP {
		return device.DesiredAP != nil && device.DesiredSwitch == nil
	}
	return family == network.FamilySwitch && device.DesiredSwitch != nil && device.DesiredAP == nil
}

func cloneMutationDevice(device Device) Device {
	result := device
	result.DesiredAP = cloneAP(device.DesiredAP)
	result.DesiredSwitch = cloneSwitch(device.DesiredSwitch)
	result.wifiCopies = cloneWiFiCopies(device.wifiCopies)
	if device.Baseline != nil {
		baseline := *device.Baseline
		baseline.Bindings = profile.CloneBindings(device.Baseline.Bindings)
		result.Baseline = &baseline
	}
	return result
}

func cloneAP(config *network.APConfig) *network.APConfig {
	if config == nil {
		return nil
	}
	result := config.Clone()
	return &result
}

func cloneSwitch(config *network.SwitchConfig) *network.SwitchConfig {
	if config == nil {
		return nil
	}
	result := config.Clone()
	return &result
}

func (c *Controller) addWiFi(id network.DeviceID, request network.AddWiFiRequest) (network.ConfigVersion, error) {
	return c.mutateDesired(id, network.FamilyAP, func(device *Device) *network.ControlError {
		if request.Name == "" || request.CopyFrom == "" || request.Password == "" {
			return &network.ControlError{Code: network.InvalidConfig, Field: "networks"}
		}
		networks := device.DesiredAP.Networks.Value
		_, sourceCount := wifiIndex(networks, request.CopyFrom)
		if sourceCount != 1 {
			return &network.ControlError{Code: network.ResourceNotFound}
		}
		_, destinationCount := wifiIndex(networks, request.Name)
		if destinationCount != 0 {
			return &network.ControlError{Code: network.ResourceExists}
		}
		requestConfig := wifiMutationRequest(networks)
		target := network.WiFiNetwork{
			Name: request.Name,
			Security: network.Supplied(network.WiFiSecurity{
				PSK: network.Supplied(request.Password),
			}),
		}
		requestConfig.Networks.Value = append(requestConfig.Networks.Value, target)
		device.DesiredAP = &requestConfig
		device.wifiCopies = map[string]string{request.Name: request.CopyFrom}
		return nil
	})
}

func (c *Controller) setWiFi(id network.DeviceID, request network.SetWiFiRequest) (network.ConfigVersion, error) {
	return c.mutateDesired(id, network.FamilyAP, func(device *Device) *network.ControlError {
		if request.CurrentName == "" || request.Network.Name == "" {
			return &network.ControlError{Code: network.InvalidConfig, Field: "networks"}
		}
		networks := device.DesiredAP.Networks.Value
		index, count := wifiIndex(networks, request.CurrentName)
		if count != 1 {
			return &network.ControlError{Code: network.ResourceNotFound}
		}
		if request.Network.Name != request.CurrentName {
			_, replacementCount := wifiIndex(networks, request.Network.Name)
			if replacementCount != 0 {
				return &network.ControlError{Code: network.ResourceExists}
			}
			device.wifiCopies = map[string]string{request.Network.Name: request.CurrentName}
		}
		requestConfig := wifiMutationRequest(networks)
		requestConfig.Networks.Value[index] = cloneWiFiNetwork(request.Network)
		device.DesiredAP = &requestConfig
		return nil
	})
}

func (c *Controller) removeWiFi(id network.DeviceID, name string) (network.ConfigVersion, error) {
	return c.mutateDesired(id, network.FamilyAP, func(device *Device) *network.ControlError {
		if name == "" {
			return &network.ControlError{Code: network.InvalidConfig, Field: "networks"}
		}
		networks := device.DesiredAP.Networks.Value
		index, count := wifiIndex(networks, name)
		if count != 1 {
			return &network.ControlError{Code: network.ResourceNotFound}
		}
		requestConfig := wifiMutationRequest(networks)
		requestConfig.Networks.Value = slices.Delete(requestConfig.Networks.Value, index, index+1)
		device.DesiredAP = &requestConfig
		return nil
	})
}

func (c *Controller) setRadio(id network.DeviceID, request network.RadioConfig) (network.ConfigVersion, error) {
	return c.mutateDesired(id, network.FamilyAP, func(device *Device) *network.ControlError {
		index, count := radioIndex(device.DesiredAP.Radios.Value, request)
		if count == 0 {
			return &network.ControlError{Code: network.ResourceNotFound}
		}
		if count != 1 {
			return &network.ControlError{Code: network.InvalidConfig, Field: "radios"}
		}
		prior := device.DesiredAP.Radios.Value[index]
		if request.ID != "" && prior.ID != request.ID || request.Band != "" && prior.Band != request.Band {
			return &network.ControlError{Code: network.InvalidConfig, Field: "radios"}
		}
		request.ID, request.Band = prior.ID, prior.Band
		requestConfig := radioMutationRequest(device.DesiredAP.Radios.Value)
		requestConfig.Radios.Value[index] = request
		device.DesiredAP = &requestConfig
		return nil
	})
}

func (c *Controller) setSwitchPort(id network.DeviceID, request network.SwitchPortConfig) (network.ConfigVersion, error) {
	return c.mutateDesired(id, network.FamilySwitch, func(device *Device) *network.ControlError {
		ports := device.DesiredSwitch.Ports.Value
		index := slices.IndexFunc(ports, func(port network.SwitchPortConfig) bool { return port.Index == request.Index })
		if index < 0 {
			return &network.ControlError{Code: network.ResourceNotFound}
		}
		requestConfig := portMutationRequest(ports)
		requestConfig.Ports.Value[index] = request
		device.DesiredSwitch = &requestConfig
		return nil
	})
}

func (c *Controller) wifiNetworks(id network.DeviceID) ([]network.WiFiNetworkView, error) {
	mac, err := normalizeMAC(string(id))
	if err != nil {
		return nil, &network.ControlError{Code: network.InvalidDevice}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	device, exists := c.devices[mac]
	if !exists {
		return nil, &network.ControlError{Code: network.NotRegistered}
	}
	if device.Family != network.FamilyAP {
		return nil, &network.ControlError{Code: network.FamilyMismatch}
	}
	if device.DesiredAP == nil {
		return nil, &network.ControlError{Code: network.DesiredStateMissing}
	}
	if device.Baseline == nil || !device.Baseline.TypedReady {
		return nil, &network.ControlError{Code: network.BaselineUnusable}
	}
	values, err := configmap.Parse(device.Baseline.Config.System)
	if err != nil {
		return nil, &network.ControlError{Code: network.BaselineUnusable}
	}
	views := make([]network.WiFiNetworkView, 0, len(device.DesiredAP.Networks.Value))
	for _, wifi := range device.DesiredAP.Networks.Value {
		policy := resolvedWiFiViewPolicy(values, device.Baseline.Bindings, wifi.Name)
		view := network.WiFiNetworkView{
			Name: wifi.Name, Enabled: policy.Enabled, VLAN: policy.VLAN, SecurityMode: policy.SecurityMode,
			Bands: slices.Clone(wifi.Bands.Value), RadioIDs: slices.Clone(wifi.RadioIDs.Value),
		}
		views = append(views, view)
	}
	slices.SortFunc(views, func(left, right network.WiFiNetworkView) int { return strings.Compare(left.Name, right.Name) })
	return views, nil
}

type wifiViewPolicy struct {
	Enabled      network.Optional[bool]
	VLAN         network.Optional[network.VLANID]
	SecurityMode network.Optional[network.WiFiSecurityMode]
}

type wifiViewStatus string

const (
	wifiViewEnabled  wifiViewStatus = "enabled"
	wifiViewDisabled wifiViewStatus = "disabled"
)

func resolvedWiFiViewPolicy(values configmap.Values, bindings []profile.ResourceBinding, name string) wifiViewPolicy {
	var result wifiViewPolicy
	seen := false
	for _, binding := range bindings {
		if binding.Kind != "wifi" || binding.Identity != name || len(binding.Prefixes) < 2 {
			continue
		}
		candidate := decodeWiFiViewPolicy(values, binding.Prefixes[0], binding.Prefixes[1])
		if !seen {
			result, seen = candidate, true
			continue
		}
		if result.Enabled != candidate.Enabled {
			result.Enabled = network.Optional[bool]{}
		}
		if result.VLAN != candidate.VLAN {
			result.VLAN = network.Optional[network.VLANID]{}
		}
		if result.SecurityMode != candidate.SecurityMode {
			result.SecurityMode = network.Optional[network.WiFiSecurityMode]{}
		}
	}
	return result
}

func decodeWiFiViewPolicy(values configmap.Values, wireless, aaa string) wifiViewPolicy {
	var result wifiViewPolicy
	wirelessStatus, wirelessStatusPresent := values[wireless+"status"]
	aaaStatus, aaaStatusPresent := values[aaa+"status"]
	if wirelessStatusPresent && aaaStatusPresent && wirelessStatus == aaaStatus {
		switch wifiViewStatus(wirelessStatus) {
		case wifiViewEnabled:
			result.Enabled = network.Supplied(true)
		case wifiViewDisabled:
			result.Enabled = network.Supplied(false)
		}
	}
	if bridge, present := values[aaa+"br.devname"]; present {
		if bridge == "br0" {
			result.VLAN = network.Cleared[network.VLANID]()
		} else if suffix, found := strings.CutPrefix(bridge, "br0."); found {
			if parsed, err := strconv.ParseUint(suffix, 10, 16); err == nil && parsed > 0 && parsed < 4095 {
				result.VLAN = network.Supplied(network.VLANID(parsed))
			}
		}
	}
	if values[aaa+"wpa"] == "2" && values[aaa+"wpa.1.pairwise"] == "CCMP" && values[aaa+"wpa.key.1.mgmt"] == "WPA-PSK" {
		result.SecurityMode = network.Supplied(network.WPA2Personal)
	}
	return result
}

func wifiIndex(networks []network.WiFiNetwork, name string) (int, int) {
	index, count := -1, 0
	for candidateIndex, wifi := range networks {
		if wifi.Name == name {
			index, count = candidateIndex, count+1
		}
	}
	return index, count
}

func radioIndex(radios []network.RadioConfig, request network.RadioConfig) (int, int) {
	index, count := -1, 0
	for candidateIndex, radio := range radios {
		matches := request.ID != "" && radio.ID == request.ID || request.ID == "" && radio.Band == request.Band
		if matches {
			index, count = candidateIndex, count+1
		}
	}
	return index, count
}

func cloneWiFiNetwork(wifi network.WiFiNetwork) network.WiFiNetwork {
	config := network.APConfig{Networks: network.Supplied([]network.WiFiNetwork{wifi})}.Clone()
	return config.Networks.Value[0]
}

func wifiMutationRequest(networks []network.WiFiNetwork) network.APConfig {
	identities := make([]network.WiFiNetwork, len(networks))
	for index, wifi := range networks {
		identities[index].Name = wifi.Name
	}
	return network.APConfig{Networks: network.Supplied(identities)}
}

func radioMutationRequest(radios []network.RadioConfig) network.APConfig {
	identities := make([]network.RadioConfig, len(radios))
	for index, radio := range radios {
		identities[index].ID, identities[index].Band = radio.ID, radio.Band
	}
	return network.APConfig{Radios: network.Supplied(identities)}
}

func portMutationRequest(ports []network.SwitchPortConfig) network.SwitchConfig {
	identities := make([]network.SwitchPortConfig, len(ports))
	for index, port := range ports {
		identities[index].Index = port.Index
	}
	return network.SwitchConfig{Ports: network.Supplied(identities)}
}

func sortDesiredResources(device *Device, descriptor profile.DeviceDescriptor) {
	if device.DesiredAP != nil {
		radios := device.DesiredAP.Radios.Value
		sort.SliceStable(radios, func(i, j int) bool {
			leftInterface := resolvedRadioInterface(descriptor, radios[i])
			rightInterface := resolvedRadioInterface(descriptor, radios[j])
			return leftInterface+"\x00"+string(radios[i].ID) < rightInterface+"\x00"+string(radios[j].ID)
		})
	}
	if device.DesiredSwitch != nil {
		slices.SortFunc(device.DesiredSwitch.Ports.Value, func(left, right network.SwitchPortConfig) int {
			return int(left.Index) - int(right.Index)
		})
	}
}

func resolvedRadioInterface(descriptor profile.DeviceDescriptor, radio network.RadioConfig) string {
	for _, capability := range descriptor.Radios {
		if radio.ID != "" && capability.ID == string(radio.ID) {
			return capability.Interface
		}
	}
	for _, capability := range descriptor.Radios {
		if capability.Band == radio.Band {
			return capability.Interface
		}
	}
	return strconv.Itoa(len(descriptor.Radios))
}
