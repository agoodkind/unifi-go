// Package ap compiles access point configuration from reported capabilities.
package ap

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"

	"github.com/GehirnInc/crypt/sha512_crypt"

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

func (compiler) Compile(descriptor profile.DeviceDescriptor, config network.APConfig, secrets profile.SecretReader) (profile.SetParam, error) {
	if !New().Supports(descriptor) {
		return profile.SetParam{}, fmt.Errorf("unsupported access point configuration protocol")
	}
	if err := config.Validate(); err != nil {
		slog.Error("access point configuration validation failed", "error", err)
		return profile.SetParam{}, fmt.Errorf("validate access point configuration: %w", err)
	}
	if secrets == nil && (len(config.Networks) > 0 || config.SSH != nil) {
		return profile.SetParam{}, fmt.Errorf("secret reader is required")
	}
	if len(descriptor.Radios) == 0 {
		return profile.SetParam{}, fmt.Errorf("no reported radios")
	}
	physical, err := reportedRadios(descriptor, config.Radios)
	if err != nil {
		return profile.SetParam{}, err
	}
	if err := validateDescriptorValues(descriptor, physical); err != nil {
		return profile.SetParam{}, err
	}

	system := baseSystem()
	bridgeMembers := wiredInterfaces(descriptor)
	writeSystemDefaults(system, descriptor, config.CountryCode)
	configuredRadios, err := writeConfiguredRadios(system, config, physical, descriptor)
	if err != nil {
		return profile.SetParam{}, err
	}
	vlanMembers, wirelessBridgeMembers, err := writeNetworks(system, config.Networks, configuredRadios, physical, secrets, 2+len(wiredInterfaces(descriptor)))
	if err != nil {
		return profile.SetParam{}, err
	}
	bridgeMembers = append(bridgeMembers, wirelessBridgeMembers...)
	writeBridge(system, 1, "br0", bridgeMembers)
	writeNetconf(system, 1, "br0", true)
	for wiredIndex, wired := range wiredInterfaces(descriptor) {
		writeNetconf(system, wiredIndex+2, wired, true)
	}
	writeVLANs(system, descriptor, vlanMembers, configuredVAPCount(config.Networks))
	if err := writeSSH(system, config.SSH, secrets); err != nil {
		return profile.SetParam{}, err
	}
	param := profile.SetParam{Version: "", Management: configmap.Values{}, System: system}
	version, err := profile.CanonicalVersion(param)
	if err != nil {
		return profile.SetParam{}, fmt.Errorf("derive configuration version: %w", err)
	}
	param.Version = version
	return param, nil
}

func reportedRadios(descriptor profile.DeviceDescriptor, requested []network.RadioConfig) (map[network.RadioBand]profile.RadioCapability, error) {
	physical := make(map[network.RadioBand]profile.RadioCapability, len(descriptor.Radios))
	for _, radio := range descriptor.Radios {
		if !slices.ContainsFunc(requested, func(config network.RadioConfig) bool { return config.Band == radio.Band }) {
			continue
		}
		if radio.Interface == "" {
			return nil, fmt.Errorf("radio %q lacks band or interface", radio.ID)
		}
		if _, exists := physical[radio.Band]; exists {
			return nil, fmt.Errorf("multiple reported radios for band %q", radio.Band)
		}
		physical[radio.Band] = radio
	}
	return physical, nil
}

// This compatibility evidence is limited to reproduced settings on this firmware.
// Model identity never admits a device or supplies power bounds.
func reproducedRadioSetting(descriptor profile.DeviceDescriptor, requested network.RadioConfig) bool {
	if descriptor.Model != "U7PG2" || descriptor.Firmware != "6.8.2.15592" {
		return false
	}
	channel := uint16(0)
	if requested.Channel != nil {
		channel = *requested.Channel
	}
	switch requested.Band {
	case network.Band2GHz:
		if requested.WidthMHz == network.Width20 {
			return channel == 0 || channel == 6 || channel == 11
		}
		return requested.WidthMHz == network.Width40 && channel == 6
	case network.Band5GHz:
		return requested.WidthMHz == network.Width40 && (channel == 0 || channel == 44 || channel == 157)
	default:
		return false
	}
}

func writeConfiguredRadios(values configmap.Values, config network.APConfig, physical map[network.RadioBand]profile.RadioCapability, descriptor profile.DeviceDescriptor) (map[network.RadioBand]int, error) {
	configured := make(map[network.RadioBand]int, len(config.Radios))
	requestedRadios := append([]network.RadioConfig(nil), config.Radios...)
	slices.SortFunc(requestedRadios, func(left network.RadioConfig, right network.RadioConfig) int {
		return strings.Compare(physical[left.Band].Interface, physical[right.Band].Interface)
	})
	nextVAPIndex := 0
	for index, requested := range requestedRadios {
		reported, exists := physical[requested.Band]
		if !exists {
			return nil, fmt.Errorf("radios[%d].band: no reported radio for %q", index, requested.Band)
		}
		if err := validateRadioCapability(requested, reported, index, descriptor); err != nil {
			return nil, err
		}
		deviceName := virtualInterface(reported.Interface, nextVAPIndex)
		configured[requested.Band] = nextVAPIndex
		writeRadio(values, index+1, deviceName, reported.Interface, config.CountryCode, requested)
		vapCount := 0
		for _, wifi := range config.Networks {
			if slices.Contains(wifi.Bands, requested.Band) {
				vapCount++
			}
		}
		if vapCount == 0 {
			vapCount = 1
		}
		if strings.HasPrefix(deviceName, reported.Interface+"ap") {
			writePhysicalVirtualRadios(values, index+1, reported.Interface, nextVAPIndex, vapCount)
		}
		nextVAPIndex += vapCount
	}
	return configured, nil
}

func writeNetworks(values configmap.Values, networks []network.WiFiNetwork, configured map[network.RadioBand]int, physical map[network.RadioBand]profile.RadioCapability, secrets profile.SecretReader, netconfStart int) (map[network.VLANID][]string, []string, error) {
	vlans := make(map[network.VLANID][]string)
	var untagged []string
	psks, err := readNetworkPSKs(networks, secrets)
	if err != nil {
		return nil, nil, err
	}
	bands := make([]network.RadioBand, 0, len(configured))
	for band := range configured {
		bands = append(bands, band)
	}
	slices.SortFunc(bands, func(left network.RadioBand, right network.RadioBand) int {
		return strings.Compare(physical[left].Interface, physical[right].Interface)
	})
	wirelessIndex := 0
	for _, band := range bands {
		deviceIndex := configured[band]
		for networkIndex, wifi := range networks {
			if !slices.Contains(wifi.Bands, band) {
				continue
			}
			deviceName := virtualInterface(physical[band].Interface, deviceIndex)
			deviceIndex++
			wirelessIndex++
			bridgeName := "br0"
			if wifi.VLAN != nil {
				bridgeName = fmt.Sprintf("br0.%d", *wifi.VLAN)
				vlans[*wifi.VLAN] = append(vlans[*wifi.VLAN], deviceName)
			} else {
				untagged = append(untagged, deviceName)
			}
			writeWireless(values, wirelessIndex, deviceName, physical[band].Interface, bridgeName, band, wifi, psks[networkIndex])
			writeVAPEbtables(values, wirelessIndex, deviceName)
			writeNetconf(values, netconfStart+wirelessIndex-1, deviceName, false)
		}
	}
	return vlans, untagged, nil
}

func readNetworkPSKs(networks []network.WiFiNetwork, secrets profile.SecretReader) ([]string, error) {
	psks := make([]string, len(networks))
	for index, wifi := range networks {
		if strings.ContainsAny(wifi.Name, "\r\n") {
			return nil, fmt.Errorf("networks[%d].name: contains newline", index)
		}
		secret, err := secrets.ReadSecret(wifi.Security.PSK)
		if err != nil {
			slog.Error("wireless secret read failed", "network_index", index, "error", err)
			return nil, fmt.Errorf("networks[%d].security.psk: %w", index, err)
		}
		psks[index] = string(secret)
		if err := validatePSK(psks[index]); err != nil {
			return nil, fmt.Errorf("networks[%d].security.psk: %w", index, err)
		}
	}
	return psks, nil
}

func writeSSH(values configmap.Values, ssh *network.SSHConfig, secrets profile.SecretReader) error {
	if ssh == nil {
		return nil
	}
	if strings.ContainsAny(ssh.Username, "\r\n") {
		return fmt.Errorf("ssh.username: contains newline")
	}
	password, err := secrets.ReadSecret(ssh.Password)
	if err != nil {
		slog.Error("SSH secret read failed", "error", err)
		return fmt.Errorf("ssh.password: %w", err)
	}
	plainPassword := string(password)
	if plainPassword == "" || strings.ContainsAny(plainPassword, "\r\n") {
		return fmt.Errorf("ssh.password: secret is empty or contains newline")
	}
	saltDigest := sha256.Sum256([]byte(ssh.Username + "\x00" + plainPassword))
	salt := "$6$" + hex.EncodeToString(saltDigest[:8])
	passwordHash, err := sha512_crypt.New().Generate([]byte(plainPassword), []byte(salt))
	if err != nil {
		slog.Error("SSH password hashing failed", "error", err)
		return fmt.Errorf("ssh.password: hash secret: %w", err)
	}
	set(values, "sshd.status", "enabled")
	set(values, "sshd.auth.passwd", "enabled")
	set(values, "sshd.1.ifname", "br0")
	set(values, "sshd.1.status", "enabled")
	set(values, "users.status", "enabled")
	set(values, "users.1.status", "enabled")
	set(values, "users.1.name", ssh.Username)
	set(values, "users.1.password", passwordHash)
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

func validateRadioCapability(requested network.RadioConfig, reported profile.RadioCapability, index int, descriptor profile.DeviceDescriptor) error {
	exception := reproducedRadioSetting(descriptor, requested)
	if requested.Channel != nil && !slices.Contains(reported.Channels, *requested.Channel) && (len(reported.Channels) != 0 || !exception) {
		return fmt.Errorf("radios[%d].channel: requested channel lacks capability evidence", index)
	}
	if !slices.Contains(reported.Widths, requested.WidthMHz) && (len(reported.Widths) != 0 || !exception) {
		return fmt.Errorf("radios[%d].width_mhz: requested width lacks capability evidence", index)
	}
	if requested.Power.Mode == network.PowerExplicit && requested.Power.DBm != nil {
		if reported.MinPowerDBm == nil || reported.MaxPowerDBm == nil {
			return fmt.Errorf("radios[%d].power.dbm: power bounds are not reported", index)
		}
		if reported.MinPowerDBm != nil && *requested.Power.DBm < *reported.MinPowerDBm {
			return fmt.Errorf("radios[%d].power.dbm: below reported minimum", index)
		}
		if reported.MaxPowerDBm != nil && *requested.Power.DBm > *reported.MaxPowerDBm {
			return fmt.Errorf("radios[%d].power.dbm: above reported maximum", index)
		}
	}
	return nil
}

func writeRadio(values configmap.Values, index int, deviceName string, interfaceName string, country uint16, radio network.RadioConfig) {
	prefix := fmt.Sprintf("radio.%d.", index)
	set(values, prefix+"phyname", interfaceName)
	set(values, prefix+"devname", deviceName)
	set(values, prefix+"countrycode", strconv.Itoa(int(country)))
	set(values, prefix+"status", enabled(radio.Enabled))
	channel := "auto"
	if radio.Channel != nil {
		channel = strconv.Itoa(int(*radio.Channel))
	}
	set(values, prefix+"channel", channel)
	set(values, prefix+"clksel", "1")
	set(values, prefix+"cwm.mode", widthMode(radio.Band, radio.WidthMHz))
	set(values, prefix+"ieee_mode", ieeeMode(radio.Band, radio.WidthMHz))
	set(values, prefix+"txpower_mode", string(radio.Power.Mode))
	power := "auto"
	if radio.Power.Mode == network.PowerExplicit && radio.Power.DBm != nil {
		power = strconv.Itoa(*radio.Power.DBm)
		set(values, prefix+"txpower_mode", "custom")
	}
	set(values, prefix+"txpower", power)
	for key, value := range map[string]string{
		"ack.auto": "disabled", "acktimeout": "64", "ampdu.status": "enabled",
		"antenna": "-1", "antenna.gain": "3", "bcmc_l2_filter.status": "enabled",
		"bgscan.status": "disabled", "cwm.enable": "0", "forbiasauto": "0",
		"hard_noisefloor.status": "disabled", "mode": "master", "rate.auto": "enabled",
		"rate.mcs": "auto", "rfscan": "disabled",
	} {
		set(values, prefix+key, value)
	}
}

func writeWireless(values configmap.Values, index int, deviceName string, parent string, bridge string, band network.RadioBand, wifi network.WiFiNetwork, psk string) {
	prefix := fmt.Sprintf("wireless.%d.", index)
	set(values, prefix+"devname", deviceName)
	set(values, prefix+"parent", parent)
	set(values, prefix+"ssid", wifi.Name)
	set(values, prefix+"status", enabled(wifi.Enabled))
	set(values, prefix+"mode", "master")
	set(values, prefix+"security", "none")
	iappDigest := sha256.Sum256([]byte(wifi.Name + "\x00" + psk))
	iappKey := hex.EncodeToString(iappDigest[:16])
	for key, value := range map[string]string{
		"addmtikie": "disabled", "authmode": "1", "autowds": "disabled",
		"element_adopt": "disabled", "hide_ssid": "false", "is_guest": "false",
		"l2_isolation": "disabled", "mac_acl.policy": "deny", "mac_acl.status": "enabled",
		"mcast.enhance": "0", "mcastrate": "auto", "multicast.inspect": "false",
		"no2ghz_oui": "disabled", "schedule_enabled": "disabled", "uapsd": "disabled",
		"usage": "user", "vport": "disabled", "vwire": "disabled", "wds": "disabled",
		"wmm": "enabled",
	} {
		set(values, prefix+key, value)
	}
	if wifi.Bands != nil {
		set(values, prefix+"id", "2")
	}
	if band == network.Band2GHz {
		for key, value := range map[string]string{
			"beacon_rate": "1000", "dtim_period": "1", "mgmt_rate": "1000",
			"minrate_cck_rates.status": "true", "minrate_data": "1000",
			"pureg": "0", "puren": "0",
		} {
			set(values, prefix+key, value)
		}
	} else {
		set(values, prefix+"dtim_period", "3")
		set(values, prefix+"pureg", "1")
		set(values, prefix+"puren", "0")
	}
	aaa := fmt.Sprintf("aaa.%d.", index)
	set(values, aaa+"devname", deviceName)
	set(values, aaa+"br.devname", bridge)
	set(values, aaa+"ssid", wifi.Name)
	set(values, aaa+"status", enabled(wifi.Enabled))
	set(values, aaa+"wpa", "2")
	set(values, aaa+"wpa.1.pairwise", "CCMP")
	set(values, aaa+"wpa.key.1.mgmt", "WPA-PSK")
	set(values, aaa+"wpa.psk", psk)
	for key, value := range map[string]string{
		"11k.status": "disabled", "bss_transition": "enabled", "country_beacon": "disabled",
		"driver": "madwifi", "eapol_version": "2", "ft.status": "disabled",
		"hide_ssid": "false", "iapp_key": iappKey, "id": "2", "is_guest": "false",
		"p2p": "disabled", "p2p_cross_connect": "disabled", "pmf.cipher": "AES-128-CMAC",
		"pmf.mode": "0", "pmf.status": "disabled", "proxy_arp": "disabled",
		"radius.macacl.status": "disabled", "tdls_prohibit": "disabled", "verbose": "2",
		"wpa.group_rekey": "3600",
	} {
		set(values, aaa+key, value)
	}
}

func writePhysicalVirtualRadios(values configmap.Values, radioIndex int, physicalInterface string, firstVAPIndex int, vapCount int) {
	for virtualIndex := 1; virtualIndex < vapCount; virtualIndex++ {
		prefix := fmt.Sprintf("radio.%d.virtual.%d.", radioIndex, virtualIndex)
		set(values, prefix+"devname", virtualInterface(physicalInterface, firstVAPIndex+virtualIndex))
		set(values, prefix+"mode", "master")
		set(values, prefix+"status", "enabled")
	}
}

func writeVAPEbtables(values configmap.Values, vapIndex int, deviceName string) {
	firstCommand := vapIndex*2 - 1
	set(values, fmt.Sprintf("ebtables.%d.cmd", firstCommand), fmt.Sprintf("-t nat -A PREROUTING --in-interface %s -d BGA -j DROP", deviceName))
	set(values, fmt.Sprintf("ebtables.%d.cmd", firstCommand+1), fmt.Sprintf("-t nat -A POSTROUTING --out-interface %s -d BGA -j DROP", deviceName))
}

func writeNetconf(values configmap.Values, index int, deviceName string, up bool) {
	prefix := fmt.Sprintf("netconf.%d.", index)
	set(values, prefix+"autoip.status", "disabled")
	set(values, prefix+"devname", deviceName)
	set(values, prefix+"ip", "0.0.0.0")
	set(values, prefix+"status", "enabled")
	set(values, prefix+"up", enabled(up))
	if deviceName != "br0" {
		set(values, prefix+"promisc", "enabled")
	}
}

func writeBridge(values configmap.Values, index int, name string, members []string) {
	prefix := fmt.Sprintf("bridge.%d.", index)
	set(values, prefix+"devname", name)
	set(values, prefix+"fd", "1")
	set(values, prefix+"stp.status", "disabled")
	for memberIndex, member := range members {
		set(values, fmt.Sprintf("%sport.%d.devname", prefix, memberIndex+1), member)
	}
}

func writeVLANs(values configmap.Values, descriptor profile.DeviceDescriptor, vlanMembers map[network.VLANID][]string, vapCount int) {
	vlanIndex := 0
	bridgeIndex := 1
	netconfIndex := 1 + vapCount + len(wiredInterfaces(descriptor))
	vlans := make([]network.VLANID, 0, len(vlanMembers))
	for vlan := range vlanMembers {
		vlans = append(vlans, vlan)
	}
	slices.Sort(vlans)
	for _, vlan := range vlans {
		wirelessMembers := vlanMembers[vlan]
		bridgeIndex++
		members := append([]string(nil), wirelessMembers...)
		for _, wired := range wiredInterfaces(descriptor) {
			vlanIndex++
			vlanName := fmt.Sprintf("%s.%d", wired, vlan)
			set(values, fmt.Sprintf("vlan.%d.devname", vlanIndex), wired)
			set(values, fmt.Sprintf("vlan.%d.id", vlanIndex), strconv.Itoa(int(vlan)))
			members = append(members, vlanName)
		}
		writeBridge(values, bridgeIndex, fmt.Sprintf("br0.%d", vlan), members)
		netconfIndex++
		writeNetconf(values, netconfIndex, fmt.Sprintf("br0.%d", vlan), true)
		for _, member := range wiredInterfaces(descriptor) {
			netconfIndex++
			writeNetconf(values, netconfIndex, fmt.Sprintf("%s.%d", member, vlan), true)
		}
	}
	set(values, "vlan.status", enabled(len(vlanMembers) > 0))
}

func configuredVAPCount(networks []network.WiFiNetwork) int {
	count := 0
	for _, wifi := range networks {
		count += len(wifi.Bands)
	}
	return count
}

func wiredInterfaces(descriptor profile.DeviceDescriptor) []string {
	var result []string
	for _, port := range descriptor.Ports {
		if port.Interface != "" && !slices.Contains(result, port.Interface) {
			result = append(result, port.Interface)
		}
	}
	return result
}

func baseSystem() configmap.Values {
	return configmap.Values{"radio.status": "enabled", "wireless.status": "enabled", "aaa.status": "enabled", "bridge.status": "enabled", "netconf.status": "enabled"}
}

func writeSystemDefaults(values configmap.Values, descriptor profile.DeviceDescriptor, countryCode uint16) {
	writeConnectivityDefaults(values, descriptor.UplinkInterface)
	writeNetworkServiceDefaults(values)
	writeFilterDefaults(values)
	writeLocaleDefaults(values)
	writeRadioDefaults(values, countryCode)
	writeResolverDefaults(values)
	writeSwitchDefaults(values)
	writeRuntimeDefaults(values)
}

func writeConnectivityDefaults(values configmap.Values, uplinkInterface string) {
	if uplinkInterface == "" {
		set(values, "connectivity.status", "disabled")
		return
	}
	set(values, "connectivity.status", "enabled")
	set(values, "connectivity.uplink_bridge", "br0")
	set(values, "connectivity.uplink_eth", uplinkInterface)
}

func writeNetworkServiceDefaults(values configmap.Values) {
	for key, value := range map[string]string{
		"dhcpc.status": "enabled", "dhcpc.1.devname": "br0", "dhcpc.1.status": "enabled",
		"dnsmasq.status": "disabled", "ntpclient.status": "disabled",
		"redirector.status": "disabled", "route.status": "enabled",
	} {
		set(values, key, value)
	}
}

func writeFilterDefaults(values configmap.Values) {
	for key, value := range map[string]string{
		"ebtables.add_vlan.status": "disabled",
		"ebtables.status":          "enabled", "ip6tables.status": "disabled", "ipset.status": "disabled",
		"iptables.status": "disabled", "macacl.status": "disabled",
	} {
		set(values, key, value)
	}
}

func writeLocaleDefaults(values configmap.Values) {
	set(values, "locale.timezone", "UTC0")
	set(values, "system.timezone", "UTC0")
}

func writeRadioDefaults(values configmap.Values, countryCode uint16) {
	set(values, "radio.outdoor", "disabled")
	set(values, "radio.countrycode", strconv.Itoa(int(countryCode)))
}

func writeResolverDefaults(values configmap.Values) {
	for key, value := range map[string]string{
		"resolv.nameserver.1.status": "disabled",
		"resolv.nameserver.2.status": "disabled", "resolv.status": "enabled",
	} {
		set(values, key, value)
	}
}

func writeSwitchDefaults(values configmap.Values) {
	for key, value := range map[string]string{
		"switch.status":      "disabled",
		"switch.vlan.status": "disabled", "switch.dot1x.status": "disabled",
		"switch.jumboframes": "disabled",
	} {
		set(values, key, value)
	}
}

func writeRuntimeDefaults(values configmap.Values) {
	for key, value := range map[string]string{
		"mesh.status": "disabled", "qos.status": "disabled", "stamgr.status": "disabled",
		"system.analytics.status": "disabled",
	} {
		set(values, key, value)
	}
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

func set(values configmap.Values, key string, value string) { _ = values.Set(key, value) }

func validateDescriptorValues(descriptor profile.DeviceDescriptor, radios map[network.RadioBand]profile.RadioCapability) error {
	probe := configmap.Values{}
	for band, radio := range radios {
		if err := probe.Set("radio", radio.Interface); err != nil {
			slog.Error("reported radio interface validation failed", "band", band, "error", err)
			return fmt.Errorf("reported radio interface: %w", err)
		}
	}
	for index, port := range descriptor.Ports {
		if err := probe.Set("port", port.Interface); err != nil {
			slog.Error("reported port interface validation failed", "port_index", index, "error", err)
			return fmt.Errorf("reported ports[%d].interface: %w", index, err)
		}
	}
	if err := probe.Set("uplink", descriptor.UplinkInterface); err != nil {
		slog.Error("reported uplink interface validation failed", "error", err)
		return fmt.Errorf("reported uplink interface: %w", err)
	}
	return nil
}
