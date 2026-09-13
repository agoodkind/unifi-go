// Package profile routes device families to capability-driven configuration compilers.
package profile

import (
	"goodkind.io/unifi-go/internal/configmap"
	"goodkind.io/unifi-go/internal/informmodel"
	"goodkind.io/unifi-go/network"
)

// DeviceDescriptor contains reported identity and capabilities used for compilation.
type DeviceDescriptor struct {
	Family          network.DeviceFamily `json:"family"`
	Model           string               `json:"model"`
	Firmware        string               `json:"firmware"`
	UplinkInterface string               `json:"uplink_interface"`
	Protocol        ProtocolCapabilities `json:"protocol"`
	Radios          []RadioCapability    `json:"radios"`
	Ports           []PortCapability     `json:"ports"`
}

// ResourceBinding associates typed identity with persisted configuration records.
type ResourceBinding struct {
	Kind     string   `json:"kind"`
	Identity string   `json:"identity"`
	RadioID  string   `json:"radio_id,omitempty"`
	Prefixes []string `json:"prefixes"`
}

// ProtocolCapabilities describes the reported configuration protocol surface.
type ProtocolCapabilities struct {
	PacketVersion    uint32 `json:"packet_version"`
	PayloadVersion   uint32 `json:"payload_version"`
	SystemConfig     bool   `json:"system_config"`
	ManagementConfig bool   `json:"management_config"`
}

// RadioCapability describes one physical radio's explicit capabilities.
type RadioCapability struct {
	ID          string                    `json:"id"`
	Interface   string                    `json:"interface"`
	Band        network.RadioBand         `json:"band"`
	Channels    []uint16                  `json:"channels"`
	Widths      []network.ChannelWidthMHz `json:"widths"`
	MinPowerDBm *int                      `json:"min_power_dbm"`
	MaxPowerDBm *int                      `json:"max_power_dbm"`
}

// PortCapability describes one physical switch port's explicit capabilities.
type PortCapability struct {
	Index     uint16            `json:"index"`
	Interface string            `json:"interface"`
	VLAN      *bool             `json:"vlan"`
	PoEModes  []network.PoEMode `json:"poe_modes"`
}

// SetParam contains the two encoded device configuration namespaces.
type SetParam struct {
	Version    network.ConfigVersion
	Management configmap.Values
	System     configmap.Values
}

// SecretReader reads secret file references during compilation.
type SecretReader interface {
	ReadSecret(network.SecretFile) ([]byte, error)
}

// APCompiler compiles and decodes access point configuration and state.
type APCompiler interface {
	Supports(DeviceDescriptor) bool
	Compile(DeviceDescriptor, network.APConfig, SecretReader) (SetParam, error)
	Decode(informmodel.Report) (network.APSnapshot, error)
}

// SwitchCompiler compiles and decodes switch configuration and state.
type SwitchCompiler interface {
	Supports(DeviceDescriptor) bool
	Compile(DeviceDescriptor, network.SwitchConfig, SecretReader) (SetParam, error)
	Decode(informmodel.Report) (network.SwitchSnapshot, error)
}
