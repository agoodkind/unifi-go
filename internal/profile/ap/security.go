package ap

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"goodkind.io/unifi-go/internal/configmap"
	"goodkind.io/unifi-go/internal/profile"
	"goodkind.io/unifi-go/network"
)

// securityRecords holds the authentication records one security mode writes.
// The firmware configuration generator reads these keys and emits the matching
// hostapd wpa_key_mgmt and ieee80211w settings. protectedFrames carries the
// ieee80211w value: 0 disabled, 1 optional, 2 required.
type securityRecords struct {
	keyManagement   string
	wpa3Support     bool
	wpa3Transition  bool
	protectedFrames int
}

func securityModeRecords(mode network.WiFiSecurityMode) (securityRecords, bool) {
	switch mode {
	case network.WPA2Personal:
		return securityRecords{keyManagement: "WPA-PSK", wpa3Support: false, wpa3Transition: false, protectedFrames: 0}, true
	case network.WPA3Personal:
		return securityRecords{keyManagement: "SAE", wpa3Support: true, wpa3Transition: false, protectedFrames: 2}, true
	case network.WPA2WPA3Personal:
		return securityRecords{keyManagement: "WPA-PSK SAE", wpa3Support: true, wpa3Transition: true, protectedFrames: 1}, true
	default:
		return securityRecords{keyManagement: "", wpa3Support: false, wpa3Transition: false, protectedFrames: 0}, false
	}
}

// supportedModes lists every security mode this compiler writes and reads back.
var supportedModes = []network.WiFiSecurityMode{network.WPA2Personal, network.WPA3Personal, network.WPA2WPA3Personal}

// supportedKeyManagement reports whether a key management record came from one
// of the supported security modes.
func supportedKeyManagement(value string) bool {
	for _, mode := range supportedModes {
		records, known := securityModeRecords(mode)
		if known && records.keyManagement == value {
			return true
		}
	}
	return false
}

func overlaySecurity(values configmap.Values, wireless, aaa string, security network.WiFiSecurity, secrets profile.SecretReader) error {
	if security.Mode.Present {
		records, known := securityModeRecords(security.Mode.Value)
		if !known {
			return fmt.Errorf("networks: unknown security mode %q", security.Mode.Value)
		}
		values[wireless+"security"], values[aaa+"wpa"], values[aaa+"wpa.1.pairwise"] = "none", "2", "CCMP"
		values[aaa+"wpa.key.1.mgmt"] = records.keyManagement
		values[aaa+"wpa3.support"] = enabled(records.wpa3Support)
		values[aaa+"wpa3.transition"] = enabled(records.wpa3Transition)
		values[aaa+"pmf.status"] = enabled(records.protectedFrames > 0)
		values[aaa+"pmf.mode"] = strconv.Itoa(records.protectedFrames)
	}
	if !security.PSK.Present {
		return nil
	}
	if secrets == nil {
		return &network.ControlError{Code: network.FileReadFailed, Field: "networks"}
	}
	psk, err := secrets.ReadSecret(security.PSK.Value)
	if err != nil {
		return &network.ControlError{Code: network.FileReadFailed, Field: "networks"}
	}
	if err := validatePSK(string(psk)); err != nil {
		return err
	}
	values[aaa+"wpa.psk"] = string(psk)
	return nil
}

func validatePSK(psk string) error {
	if strings.ContainsAny(psk, "\r\n") {
		return fmt.Errorf("secret contains newline")
	}
	if len(psk) >= 8 && len(psk) <= 63 {
		return nil
	}
	if len(psk) == 64 {
		if _, err := hex.DecodeString(psk); err == nil {
			return nil
		}
	}
	return fmt.Errorf("must contain 8 through 63 bytes or 64 hexadecimal characters")
}
