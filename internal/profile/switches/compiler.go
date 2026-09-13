// Package switches compiles switch configuration from reported capabilities.
package switches

import (
	"fmt"
	"log/slog"
	"slices"
	"strconv"

	"goodkind.io/unifi-go/internal/configmap"
	"goodkind.io/unifi-go/internal/profile"
	"goodkind.io/unifi-go/network"
)

type compiler struct{}

// New returns the shared capability-driven switch compiler.
func New() profile.SwitchCompiler { return compiler{} }

func (compiler) Supports(descriptor profile.DeviceDescriptor) bool {
	return descriptor.Family == network.FamilySwitch && descriptor.Protocol.PacketVersion <= 1 && descriptor.Protocol.PayloadVersion == 1 && descriptor.Protocol.SystemConfig && descriptor.Protocol.ManagementConfig
}

func (compiler) Compile(descriptor profile.DeviceDescriptor, input profile.CompilationInput, request network.SwitchConfig, secrets profile.SecretReader) (profile.Compilation, error) {
	if !New().Supports(descriptor) {
		return profile.Compilation{}, fmt.Errorf("unsupported switch configuration protocol")
	}
	if err := request.Validate(); err != nil {
		slog.Warn("configuration composition failed")
		return profile.Compilation{}, fmt.Errorf("compose switch: %w", err)
	}
	if input.AP != nil {
		return profile.Compilation{}, &network.ControlError{Code: network.BaselineUnusable, Field: ""}
	}
	param, err := profile.CloneBaseline(input)
	if err != nil {
		slog.Warn("configuration composition failed")
		return profile.Compilation{}, fmt.Errorf("compose switch: %w", err)
	}
	prior := profile.MergeSwitch(input.Switch, network.SwitchConfig{})
	effective := profile.MergeSwitch(input.Switch, request)
	bindings, err := resolvePorts(param.System, prior)
	if err != nil {
		slog.Warn("configuration composition failed")
		return profile.Compilation{}, fmt.Errorf("compose switch: %w", err)
	}
	for _, stored := range input.Bindings {
		index := slices.IndexFunc(bindings, func(binding profile.ResourceBinding) bool {
			return binding.Kind == stored.Kind && binding.Identity == stored.Identity
		})
		if index < 0 || !slices.Equal(bindings[index].Prefixes, stored.Prefixes) {
			return profile.Compilation{}, &network.ControlError{Code: network.BaselineUnusable, Field: ""}
		}
	}
	if request.Ports.Present {
		for _, old := range prior.Ports.Value {
			if slices.ContainsFunc(effective.Ports.Value, func(port network.SwitchPortConfig) bool { return port.Index == old.Index }) {
				continue
			}
			profile.DeleteRecord(param.System, portPrefix(old.Index))
			for _, vlan := range profile.RecordPrefixes(param.System, "switch.vlan.") {
				profile.DeleteRecord(param.System, vlan+"port."+strconv.Itoa(int(old.Index))+".")
			}
		}
	}
	requestedPorts := slices.Clone(request.Ports.Value)
	slices.SortFunc(requestedPorts, func(left, right network.SwitchPortConfig) int { return int(left.Index) - int(right.Index) })
	for _, port := range requestedPorts {
		if err := applyPortRequest(param.System, descriptor, prior, effective, port); err != nil {
			return profile.Compilation{}, err
		}
	}
	if request.SSH.Present {
		if err := profile.WriteSSH(param.System, request.SSH.Value, secrets); err != nil {
			slog.Warn("configuration composition failed")
			return profile.Compilation{}, fmt.Errorf("compose switch: %w", err)
		}
	}
	bindings, err = resolvePorts(param.System, effective)
	if err != nil {
		slog.Warn("configuration composition failed")
		return profile.Compilation{}, fmt.Errorf("compose switch: %w", err)
	}
	param.Version, err = profile.CanonicalVersion(param)
	if err != nil {
		slog.Warn("configuration composition failed")
		return profile.Compilation{}, fmt.Errorf("compose switch: %w", err)
	}
	return profile.Compilation{Param: param, Switch: &effective, AP: nil, Bindings: profile.CloneBindings(bindings)}, nil
}

func portPrefix(index uint16) string { return fmt.Sprintf("switch.port.%d.", index) }

func resolvePorts(values configmap.Values, config network.SwitchConfig) ([]profile.ResourceBinding, error) {
	var bindings []profile.ResourceBinding
	for _, port := range config.Ports.Value {
		prefix := portPrefix(port.Index)
		if values[prefix+"opmode"] == "" {
			return nil, &network.ControlError{Code: network.BaselineUnusable, Field: ""}
		}
		bindings = append(bindings, profile.ResourceBinding{Kind: "port", Identity: strconv.Itoa(int(port.Index)), RadioID: "", Prefixes: []string{prefix}})
	}
	return profile.CloneBindings(bindings), nil
}

func reportedPort(descriptor profile.DeviceDescriptor, index uint16) (profile.PortCapability, error) {
	var result profile.PortCapability
	found := false
	for _, port := range descriptor.Ports {
		if port.Index != index {
			continue
		}
		if found {
			return result, &network.ControlError{Code: network.BaselineUnusable, Field: ""}
		}
		result, found = port, true
	}
	if !found {
		return result, fmt.Errorf("ports: requested port is not reported")
	}
	return result, nil
}

func overlayPort(values configmap.Values, request, effective network.SwitchPortConfig) error {
	prefix := portPrefix(request.Index)
	if request.Enabled.Present {
		status := "disabled"
		if request.Enabled.Value {
			status = "enabled"
		}
		values[prefix+"status"] = status
	}
	if request.PoE.Present && request.PoE.Value != "" {
		mode := "auto"
		if request.PoE.Value == network.PoEOff {
			mode = "shutdown"
		}
		values[prefix+"poe"] = mode
	}
	if !request.NativeVLAN.Present && !request.TaggedVLANs.Present {
		return nil
	}
	native, err := strconv.ParseUint(values[prefix+"pvid"], 10, 16)
	oldNative := native
	if request.NativeVLAN.Present {
		native, err = uint64(request.NativeVLAN.Value), nil
	}
	if err != nil || native == 0 {
		return &network.ControlError{Code: network.PolicyRequired, Field: "ports"}
	}
	tagged, err := portTaggedVLANs(values, request, effective, network.VLANID(native))
	if err != nil {
		return err
	}
	if request.NativeVLAN.Present {
		values[prefix+"pvid"], values[prefix+"opmode"] = strconv.FormatUint(native, 10), "switch"
	}
	for _, vlan := range profile.RecordPrefixes(values, "switch.vlan.") {
		id, err := strconv.ParseUint(values[vlan+"id"], 10, 16)
		if err != nil {
			return &network.ControlError{Code: network.BaselineUnusable, Field: ""}
		}
		if !request.TaggedVLANs.Present && id != oldNative && id != native {
			continue
		}
		mode := "exclude"
		if id == native {
			mode = "untagged"
		} else if tagged[network.VLANID(id)] {
			mode = "tagged"
		}
		key := fmt.Sprintf("%sport.%d.mode", vlan, request.Index)
		// Omitted membership outside the changed native/tagged set stays absent.
		if _, exists := values[key]; exists || id == native || tagged[network.VLANID(id)] {
			values[key] = mode
		}
	}
	return nil
}

func applyPortRequest(values configmap.Values, descriptor profile.DeviceDescriptor, prior, effective network.SwitchConfig, port network.SwitchPortConfig) error {
	capability, err := reportedPort(descriptor, port.Index)
	if err != nil {
		slog.Warn("configuration composition failed")
		return fmt.Errorf("compose switch: %w", err)
	}
	current := effective.Ports.Value[slices.IndexFunc(effective.Ports.Value, func(candidate network.SwitchPortConfig) bool { return candidate.Index == port.Index })]
	if !slices.ContainsFunc(prior.Ports.Value, func(candidate network.SwitchPortConfig) bool { return candidate.Index == port.Index }) {
		complete := network.SwitchConfig{Ports: network.Supplied([]network.SwitchPortConfig{current})}
		if err := complete.ValidateComplete(); err != nil {
			slog.Warn("configuration composition failed")
			return fmt.Errorf("compose switch: %w", err)
		}
	}
	if (port.NativeVLAN.Present || port.TaggedVLANs.Present) && (capability.VLAN == nil || !*capability.VLAN) {
		return fmt.Errorf("ports: VLAN configuration lacks capability evidence")
	}
	if port.PoE.Present && port.PoE.Value != "" && !slices.Contains(capability.PoEModes, port.PoE.Value) {
		return fmt.Errorf("ports: PoE mode lacks capability evidence")
	}
	return overlayPort(values, port, current)
}

func portTaggedVLANs(values configmap.Values, request, effective network.SwitchPortConfig, native network.VLANID) (map[network.VLANID]bool, error) {
	tagged := make(map[network.VLANID]bool)
	for _, vlan := range profile.RecordPrefixes(values, "switch.vlan.") {
		if values[fmt.Sprintf("%sport.%d.mode", vlan, request.Index)] != "tagged" {
			continue
		}
		id, err := strconv.ParseUint(values[vlan+"id"], 10, 16)
		if err != nil {
			return nil, &network.ControlError{Code: network.BaselineUnusable, Field: ""}
		}
		tagged[network.VLANID(id)] = true
	}
	if request.TaggedVLANs.Present {
		clear(tagged)
		for _, vlan := range effective.TaggedVLANs.Value {
			tagged[vlan] = true
		}
	}
	if tagged[native] {
		return nil, fmt.Errorf("ports: tagged VLAN repeats native VLAN")
	}

	required := []network.VLANID{native}
	for vlan := range tagged {
		required = append(required, vlan)
	}
	slices.Sort(required)
	required = slices.Compact(required)
	for _, id := range required {
		vlan, err := profile.MatchRecord(values, "switch.vlan.", "id", strconv.Itoa(int(id)))
		if err != nil {
			slog.Warn("configuration composition failed")
			return nil, fmt.Errorf("compose switch: %w", err)
		}
		if vlan != "" {
			continue
		}
		vlan = profile.NextRecord(values, "switch.vlan.")
		values[vlan+"id"] = strconv.Itoa(int(id))
		mode := "tagged"
		if id == native {
			mode = "untagged"
		}
		values[vlan+"mode"], values[vlan+"status"] = mode, "enabled"
	}

	return tagged, nil
}
