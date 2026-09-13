package ap

import (
	"slices"
	"strings"

	"goodkind.io/unifi-go/internal/profile"
	"goodkind.io/unifi-go/network"
)

type resolvedRadio struct {
	Config     network.RadioConfig
	Capability profile.RadioCapability
}

type compilationRadios struct {
	PriorConfigured     []resolvedRadio
	PriorAvailable      []resolvedRadio
	EffectiveConfigured []resolvedRadio
	EffectiveAvailable  []resolvedRadio
}

func resolveCompilationRadios(descriptor profile.DeviceDescriptor, prior network.APConfig, effective *network.APConfig) (compilationRadios, error) {
	priorConfigured, err := resolveRadios(descriptor, prior.Radios.Value)
	if err != nil {
		return compilationRadios{}, err
	}
	effectiveConfigured, err := resolveRadios(descriptor, effective.Radios.Value)
	if err != nil {
		return compilationRadios{}, err
	}
	for index := range effectiveConfigured {
		effective.Radios.Value[index] = effectiveConfigured[index].Config
	}
	result := compilationRadios{
		PriorConfigured:     priorConfigured,
		PriorAvailable:      priorConfigured,
		EffectiveConfigured: effectiveConfigured,
		EffectiveAvailable:  effectiveConfigured,
	}
	if !prior.Radios.Present {
		result.PriorAvailable = reportedRadios(descriptor)
	}
	if !effective.Radios.Present {
		result.EffectiveAvailable = reportedRadios(descriptor)
	}
	return result, nil
}

func resolveRadios(descriptor profile.DeviceDescriptor, configs []network.RadioConfig) ([]resolvedRadio, error) {
	result := make([]resolvedRadio, 0, len(configs))
	for _, config := range configs {
		var matches []profile.RadioCapability
		for _, capability := range descriptor.Radios {
			explicitIDMatches := config.ID != "" && capability.ID == string(config.ID)
			uniqueBandCandidate := config.ID == "" && capability.Band == config.Band
			if explicitIDMatches || uniqueBandCandidate {
				matches = append(matches, capability)
			}
		}
		if len(matches) != 1 {
			return nil, &network.ControlError{Code: network.BaselineUnusable, Field: "radios"}
		}
		capability := matches[0]
		if capability.ID == "" || capability.Interface == "" || strings.ContainsAny(capability.Interface, "\r\n") || capability.Band != config.Band {
			return nil, &network.ControlError{Code: network.BaselineUnusable, Field: "radios"}
		}
		if capability.SyntheticID {
			return nil, &network.ControlError{Code: network.BaselineUnusable, Field: "radios"}
		}
		config.ID = network.RadioID(capability.ID)
		result = append(result, resolvedRadio{Config: config, Capability: capability})
	}
	return result, nil
}

func reportedRadios(descriptor profile.DeviceDescriptor) []resolvedRadio {
	result := make([]resolvedRadio, 0, len(descriptor.Radios))
	for _, capability := range descriptor.Radios {
		result = append(result, resolvedRadio{
			Config:     network.RadioConfig{ID: network.RadioID(capability.ID), Band: capability.Band},
			Capability: capability,
		})
	}
	return result
}

func resolveNetworkRadios(wifi network.WiFiNetwork, radios []resolvedRadio) ([]resolvedRadio, error) {
	var result []resolvedRadio
	var err error
	switch {
	case wifi.RadioIDs.Present && len(wifi.RadioIDs.Value) > 0:
		result, err = radiosByID(wifi.RadioIDs.Value, radios)
	case wifi.Bands.Present && len(wifi.Bands.Value) > 0:
		result, err = radiosByBand(wifi.Bands.Value, radios)
	default:
		return nil, &network.ControlError{Code: network.PolicyRequired, Field: "networks"}
	}
	if err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, &network.ControlError{Code: network.InvalidConfig, Field: "networks"}
	}
	slices.SortFunc(result, func(left, right resolvedRadio) int {
		if compared := strings.Compare(left.Capability.Interface, right.Capability.Interface); compared != 0 {
			return compared
		}
		return strings.Compare(left.Capability.ID, right.Capability.ID)
	})
	return result, nil
}

func radiosByID(identifiers []network.RadioID, radios []resolvedRadio) ([]resolvedRadio, error) {
	result := make([]resolvedRadio, 0, len(identifiers))
	for _, identifier := range identifiers {
		var matches []resolvedRadio
		for _, radio := range radios {
			if radio.Config.ID == identifier {
				matches = append(matches, radio)
			}
		}
		if len(matches) != 1 {
			return nil, &network.ControlError{Code: network.InvalidConfig, Field: "networks"}
		}
		if matches[0].Capability.SyntheticID {
			return nil, &network.ControlError{Code: network.BaselineUnusable, Field: "networks"}
		}
		result = append(result, matches[0])
	}
	return result, nil
}

func radiosByBand(bands []network.RadioBand, radios []resolvedRadio) ([]resolvedRadio, error) {
	var result []resolvedRadio
	for _, band := range bands {
		matched := false
		for _, radio := range radios {
			if radio.Config.Band != band {
				continue
			}
			if radio.Capability.SyntheticID {
				return nil, &network.ControlError{Code: network.BaselineUnusable, Field: "networks"}
			}
			matched = true
			result = append(result, radio)
		}
		if !matched {
			return nil, &network.ControlError{Code: network.InvalidConfig, Field: "networks"}
		}
	}
	return result, nil
}

func resolveRequestedRadio(request network.RadioConfig, radios []resolvedRadio) (resolvedRadio, error) {
	var result resolvedRadio
	for _, radio := range radios {
		explicitIDMatches := request.ID != "" && radio.Config.ID == request.ID
		uniqueBandCandidate := request.ID == "" && radio.Config.Band == request.Band
		if !explicitIDMatches && !uniqueBandCandidate {
			continue
		}
		if result.Capability.ID != "" {
			return resolvedRadio{}, &network.ControlError{Code: network.InvalidConfig, Field: "radios"}
		}
		result = radio
	}
	if result.Capability.ID == "" {
		return resolvedRadio{}, &network.ControlError{Code: network.InvalidConfig, Field: "radios"}
	}
	return result, nil
}
