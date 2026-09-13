package ap

import (
	"strconv"

	"goodkind.io/unifi-go/internal/configmap"
	"goodkind.io/unifi-go/network"
)

type boundRadioStatus string

const (
	boundRadioEnabled  boundRadioStatus = "enabled"
	boundRadioDisabled boundRadioStatus = "disabled"
)

type boundPowerMode string

const (
	boundPowerAuto   boundPowerMode = "auto"
	boundPowerCustom boundPowerMode = "custom"
)

func resolveBoundRadio(values configmap.Values, prefix string, resolved network.RadioConfig) network.RadioConfig {
	if !resolved.Enabled.Present {
		switch boundRadioStatus(values[prefix+"status"]) {
		case boundRadioEnabled:
			resolved.Enabled = network.Supplied(true)
		case boundRadioDisabled:
			resolved.Enabled = network.Supplied(false)
		}
	}
	if !resolved.Channel.Present {
		channel := values[prefix+"channel"]
		if channel == "auto" {
			resolved.Channel = network.Cleared[uint16]()
		} else if parsed, err := strconv.ParseUint(channel, 10, 16); err == nil && parsed > 0 {
			resolved.Channel = network.Supplied(uint16(parsed))
		}
	}
	if !resolved.WidthMHz.Present {
		mode := values[prefix+"ieee_mode"]
		if mode == ieeeMode(resolved.Band, network.Width20) {
			resolved.WidthMHz = network.Supplied(network.Width20)
		} else if mode == ieeeMode(resolved.Band, network.Width40) {
			resolved.WidthMHz = network.Supplied(network.Width40)
		}
	}
	power := resolved.Power.Value
	if !power.Mode.Present {
		switch boundPowerMode(values[prefix+"txpower_mode"]) {
		case boundPowerAuto:
			power.Mode = network.Supplied(network.PowerAuto)
		case boundPowerCustom:
			power.Mode = network.Supplied(network.PowerExplicit)
		}
	}
	if power.Mode.Present && power.Mode.Value == network.PowerExplicit && !power.DBm.Present {
		if parsed, err := strconv.Atoi(values[prefix+"txpower"]); err == nil {
			power.DBm = network.Supplied(parsed)
		}
	}
	if power.Mode.Present || power.DBm.Present {
		resolved.Power = network.Supplied(power)
	}
	return resolved
}

func validateEffectiveSecurity(values configmap.Values, aaa string) error {
	if values[aaa+"wpa"] != "2" || values[aaa+"wpa.1.pairwise"] != "CCMP" || values[aaa+"wpa.key.1.mgmt"] != "WPA-PSK" {
		return &network.ControlError{Code: network.PolicyRequired, Field: "networks"}
	}
	psk := values[aaa+"wpa.psk"]
	if psk == "" {
		return &network.ControlError{Code: network.PolicyRequired, Field: "networks"}
	}
	return validatePSK(psk)
}
