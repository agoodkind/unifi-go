// Package switches compiles switch configuration from reported capabilities.
package switches

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

type configRecord struct {
	key   string
	value string
}

// New returns the shared capability-driven switch compiler.
func New() profile.SwitchCompiler { return compiler{} }

func (compiler) Supports(descriptor profile.DeviceDescriptor) bool {
	return descriptor.Family == network.FamilySwitch && descriptor.Protocol.PacketVersion <= 1 && descriptor.Protocol.PayloadVersion == 1 && descriptor.Protocol.SystemConfig && descriptor.Protocol.ManagementConfig
}

func (compiler) Compile(descriptor profile.DeviceDescriptor, config network.SwitchConfig, secrets profile.SecretReader) (profile.SetParam, error) {
	if descriptor.Family != network.FamilySwitch {
		return profile.SetParam{}, fmt.Errorf("device family is %q", descriptor.Family)
	}
	if !New().Supports(descriptor) {
		return profile.SetParam{}, fmt.Errorf("unsupported switch configuration protocol")
	}
	if err := config.Validate(); err != nil {
		slog.Error("switch configuration validation failed", "error", err)
		return profile.SetParam{}, fmt.Errorf("validate switch configuration: %w", err)
	}
	if config.SSH != nil && secrets == nil {
		return profile.SetParam{}, fmt.Errorf("secret reader is required")
	}
	ports, err := reportedPorts(descriptor)
	if err != nil {
		return profile.SetParam{}, err
	}
	requested := append([]network.SwitchPortConfig(nil), config.Ports...)
	slices.SortFunc(requested, func(left network.SwitchPortConfig, right network.SwitchPortConfig) int {
		return int(left.Index) - int(right.Index)
	})
	if err := validateRequests(requested, ports); err != nil {
		return profile.SetParam{}, err
	}

	system := configmap.Values{}
	vlans := desiredVLANs(requested)
	if err := writeVLANs(system, vlans); err != nil {
		return profile.SetParam{}, err
	}
	if err := writePorts(system, requested, vlans); err != nil {
		return profile.SetParam{}, err
	}
	if err := writeSSH(system, config.SSH, secrets, ports); err != nil {
		return profile.SetParam{}, err
	}
	param := profile.SetParam{Version: "", Management: configmap.Values{}, System: system}
	version, err := profile.CanonicalVersion(param)
	if err != nil {
		slog.Error("switch configuration version derivation failed", "error", err)
		return profile.SetParam{}, fmt.Errorf("derive configuration version: %w", err)
	}
	param.Version = version
	return param, nil
}

func reportedPorts(descriptor profile.DeviceDescriptor) (map[uint16]profile.PortCapability, error) {
	if len(descriptor.Ports) == 0 {
		return nil, fmt.Errorf("no reported ports")
	}
	ports := make(map[uint16]profile.PortCapability, len(descriptor.Ports))
	for _, port := range descriptor.Ports {
		if port.Index == 0 {
			return nil, fmt.Errorf("reported port index must be greater than zero")
		}
		if strings.ContainsAny(port.Interface, "\r\n") {
			return nil, fmt.Errorf("reported port %d interface contains newline", port.Index)
		}
		if _, exists := ports[port.Index]; exists {
			return nil, fmt.Errorf("duplicate reported port index %d", port.Index)
		}
		ports[port.Index] = port
	}
	return ports, nil
}

func validateRequests(requested []network.SwitchPortConfig, ports map[uint16]profile.PortCapability) error {
	for requestIndex, request := range requested {
		port, exists := ports[request.Index]
		if !exists {
			return fmt.Errorf("ports[%d].index: port %d is not reported", requestIndex, request.Index)
		}
		if port.VLAN == nil || !*port.VLAN {
			return fmt.Errorf("ports[%d]: VLAN configuration lacks capability evidence", requestIndex)
		}
		if request.PoE != "" && !slices.Contains(port.PoEModes, request.PoE) {
			return fmt.Errorf("ports[%d].poe: mode %q is not reported", requestIndex, request.PoE)
		}
	}
	return nil
}

func desiredVLANs(ports []network.SwitchPortConfig) []network.VLANID {
	seen := map[network.VLANID]struct{}{1: {}}
	for _, port := range ports {
		seen[port.NativeVLAN] = struct{}{}
		for _, vlan := range port.TaggedVLANs {
			seen[vlan] = struct{}{}
		}
	}
	vlans := make([]network.VLANID, 0, len(seen))
	for vlan := range seen {
		vlans = append(vlans, vlan)
	}
	slices.Sort(vlans)
	return vlans
}

func writeVLANs(values configmap.Values, vlans []network.VLANID) error {
	for vlanIndex, vlan := range vlans {
		prefix := fmt.Sprintf("switch.vlan.%d.", vlanIndex+1)
		mode := "tagged"
		if vlan == 1 {
			mode = "untagged"
		}
		if err := setAll(values,
			configRecord{key: prefix + "id", value: strconv.Itoa(int(vlan))},
			configRecord{key: prefix + "mode", value: mode},
			configRecord{key: prefix + "status", value: "enabled"},
		); err != nil {
			return err
		}
	}
	return nil
}

func writePorts(values configmap.Values, requested []network.SwitchPortConfig, vlans []network.VLANID) error {
	for _, port := range requested {
		prefix := fmt.Sprintf("switch.port.%d.", port.Index)
		status := "disabled"
		if port.Enabled {
			status = "enabled"
		}
		if err := setAll(values,
			configRecord{key: prefix + "opmode", value: "switch"},
			configRecord{key: prefix + "status", value: status},
			configRecord{key: prefix + "pvid", value: strconv.Itoa(int(port.NativeVLAN))},
		); err != nil {
			return err
		}
		tagged := make(map[network.VLANID]struct{}, len(port.TaggedVLANs))
		for _, vlan := range port.TaggedVLANs {
			tagged[vlan] = struct{}{}
		}
		for vlanIndex, vlan := range vlans {
			mode := "exclude"
			if vlan == port.NativeVLAN {
				mode = "untagged"
			} else if _, exists := tagged[vlan]; exists {
				mode = "tagged"
			}
			key := fmt.Sprintf("switch.vlan.%d.port.%d.mode", vlanIndex+1, port.Index)
			if err := values.Set(key, mode); err != nil {
				slog.Warn("switch VLAN membership write failed", "port_index", port.Index)
				return fmt.Errorf("set switch port VLAN membership: %w", err)
			}
		}
		if port.PoE != "" {
			poe := "auto"
			if port.PoE == network.PoEOff {
				poe = "shutdown"
			}
			if err := values.Set(prefix+"poe", poe); err != nil {
				slog.Warn("switch PoE mode write failed", "port_index", port.Index)
				return fmt.Errorf("set switch port PoE mode: %w", err)
			}
		}
	}
	return nil
}

func writeSSH(values configmap.Values, ssh *network.SSHConfig, secrets profile.SecretReader, ports map[uint16]profile.PortCapability) error {
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
	plainPassword := strings.Trim(string(password), "\r\n")
	if plainPassword == "" || strings.ContainsAny(plainPassword, "\r\n") {
		return fmt.Errorf("ssh.password: secret is empty or contains newline")
	}
	interfaceName := managementInterface(ports)
	if interfaceName == "" {
		return fmt.Errorf("ssh: no reported port has an interface")
	}
	digest := sha256.Sum256([]byte(ssh.Username + "\x00" + plainPassword))
	salt := "$6$" + hex.EncodeToString(digest[:8])
	passwordHash, err := sha512_crypt.New().Generate([]byte(plainPassword), []byte(salt))
	if err != nil {
		return fmt.Errorf("ssh.password: hash secret: %w", err)
	}
	if err := setAll(values,
		configRecord{key: "sshd.status", value: "enabled"},
		configRecord{key: "sshd.auth.passwd", value: "enabled"},
		configRecord{key: "sshd.1.ifname", value: interfaceName},
		configRecord{key: "sshd.1.status", value: "enabled"},
		configRecord{key: "users.status", value: "enabled"},
		configRecord{key: "users.1.status", value: "enabled"},
		configRecord{key: "users.1.name", value: ssh.Username},
		configRecord{key: "users.1.password", value: passwordHash},
	); err != nil {
		return err
	}
	return nil
}

func managementInterface(ports map[uint16]profile.PortCapability) string {
	indices := make([]uint16, 0, len(ports))
	for index := range ports {
		indices = append(indices, index)
	}
	slices.Sort(indices)
	for _, index := range indices {
		if ports[index].Interface != "" {
			return ports[index].Interface
		}
	}
	return ""
}

func setAll(values configmap.Values, records ...configRecord) error {
	for _, record := range records {
		if err := values.Set(record.key, record.value); err != nil {
			slog.Warn("switch configuration record write failed")
			return fmt.Errorf("set switch configuration record: %w", err)
		}
	}
	return nil
}
