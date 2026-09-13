// Package informmodel defines the inform payload shared by device profiles and controllers.
package informmodel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

// Uint16Scalar accepts the numeric and quoted numeric forms used by device reports.
type Uint16Scalar uint16

// UnmarshalJSON decodes a number or a quoted number.
func (value *Uint16Scalar) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return fmt.Errorf("decode uint16 scalar: empty value")
	}
	if data[0] == '"' {
		var encoded string
		if err := json.Unmarshal(data, &encoded); err != nil {
			return fmt.Errorf("decode uint16 scalar string: %w", err)
		}
		parsed, err := strconv.ParseUint(encoded, 10, 16)
		if err != nil {
			return fmt.Errorf("decode uint16 scalar string %q: %w", encoded, err)
		}
		*value = Uint16Scalar(parsed)
		return nil
	}

	var parsed uint16
	if err := json.Unmarshal(data, &parsed); err != nil {
		return fmt.Errorf("decode uint16 scalar: %w", err)
	}
	*value = Uint16Scalar(parsed)
	return nil
}

// Report is the typed inform payload needed by profile discovery and snapshot decoding.
type Report struct {
	Type             string              `json:"type"`
	Model            string              `json:"model"`
	Version          string              `json:"version"`
	MAC              string              `json:"mac"`
	IP               string              `json:"ip"`
	Uptime           uint64              `json:"uptime"`
	ConfigVersion    string              `json:"cfgversion"`
	LastError        string              `json:"last_error"`
	CountryCode      *uint16             `json:"country_code"`
	CountryCodes     []uint16            `json:"countrycode_table"`
	RadioTable       []Radio             `json:"radio_table"`
	RadioTableStats  []RadioStats        `json:"radio_table_stats"`
	VAPTable         []VAP               `json:"vap_table"`
	PortTable        []Port              `json:"port_table"`
	EthernetTable    EthernetTable       `json:"ethernet_table"`
	Uplink           *UplinkValue        `json:"uplink"`
	SwitchCaps       *SwitchCapabilities `json:"switch_caps"`
	PacketVersion    uint32              `json:"-"`
	PayloadVersion   uint32              `json:"-"`
	SystemConfig     bool                `json:"-"`
	ManagementConfig bool                `json:"-"`
}

// UplinkValue accepts the physical interface string and emulator object forms.
type UplinkValue struct {
	Uplink
	Interface string
}

// UnmarshalJSON decodes an interface name, an uplink object, or null.
func (value *UplinkValue) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if bytes.Equal(data, []byte("null")) {
		return nil
	}
	if len(data) == 0 {
		return fmt.Errorf("decode uplink: empty value")
	}
	if data[0] == '"' {
		if err := json.Unmarshal(data, &value.Interface); err != nil {
			return fmt.Errorf("decode uplink interface: %w", err)
		}
		value.Uplink.Interface = value.Interface
		return nil
	}
	if data[0] != '{' {
		return fmt.Errorf("decode uplink: unsupported value")
	}
	var details Uplink
	if err := json.Unmarshal(data, &details); err != nil {
		return fmt.Errorf("decode uplink object: %w", err)
	}
	value.Uplink = details
	value.Interface = details.Interface
	return nil
}

// EthernetTable accepts physical and emulator report shapes.
type EthernetTable struct {
	Interface string
	Entries   []Ethernet
}

// UnmarshalJSON decodes an interface name, an entry array, or a keyed table.
func (table *EthernetTable) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return fmt.Errorf("decode ethernet table: empty value")
	}
	switch data[0] {
	case '"':
		if err := json.Unmarshal(data, &table.Interface); err != nil {
			return fmt.Errorf("decode ethernet table interface: %w", err)
		}
	case '[':
		if err := json.Unmarshal(data, &table.Entries); err != nil {
			return fmt.Errorf("decode ethernet table entries: %w", err)
		}
	case '{':
		var wrapped struct {
			Interface string     `json:"Interface"`
			Entries   []Ethernet `json:"Entries"`
		}
		if err := json.Unmarshal(data, &wrapped); err == nil && (wrapped.Interface != "" || wrapped.Entries != nil) {
			table.Interface = wrapped.Interface
			table.Entries = wrapped.Entries
			return nil
		}
		var keyed map[string]Ethernet
		if err := json.Unmarshal(data, &keyed); err != nil {
			return fmt.Errorf("decode keyed ethernet table: %w", err)
		}
		interfaceNames := make([]string, 0, len(keyed))
		for interfaceName := range keyed {
			interfaceNames = append(interfaceNames, interfaceName)
		}
		sort.Strings(interfaceNames)
		for _, interfaceName := range interfaceNames {
			entry := keyed[interfaceName]
			if entry.Name == "" {
				entry.Name = interfaceName
			}
			table.Entries = append(table.Entries, entry)
		}
	default:
		return fmt.Errorf("decode ethernet table: unsupported value")
	}
	return nil
}

// Radio describes one physical radio and its explicitly reported capabilities.
type Radio struct {
	Name       string         `json:"name"`
	Radio      string         `json:"radio"`
	Channel    *uint16        `json:"channel"`
	HT         *Uint16Scalar  `json:"ht"`
	Channels   []uint16       `json:"channels"`
	Widths     []Uint16Scalar `json:"widths"`
	MinTXPower *int           `json:"min_txpower"`
	MaxTXPower *int           `json:"max_txpower"`
	TXPower    *int           `json:"tx_power"`
	RadioCaps  *uint64        `json:"radio_caps"`
	RadioCaps2 *uint64        `json:"radio_caps2"`
}

// RadioStats contains measured radio state.
type RadioStats struct {
	Name        string  `json:"name"`
	Channel     *uint16 `json:"channel"`
	TXPower     *int    `json:"tx_power"`
	ClientCount *uint32 `json:"num_sta"`
	Noise       *int    `json:"noise"`
}

// VAP describes a virtual access point and its stations.
type VAP struct {
	Name        string        `json:"name"`
	Radio       string        `json:"radio"`
	RadioName   string        `json:"radio_name"`
	ESSID       string        `json:"essid"`
	BSSID       string        `json:"bssid"`
	Channel     *uint16       `json:"channel"`
	BW          *Uint16Scalar `json:"bw"`
	TXPower     *int          `json:"tx_power"`
	ClientCount *uint32       `json:"num_sta"`
	RxBytes     uint64        `json:"rx_bytes"`
	TxBytes     uint64        `json:"tx_bytes"`
	Up          *bool         `json:"up"`
	Stations    []Station     `json:"sta_table"`
}

// Station describes a wireless client.
type Station struct {
	MAC      string  `json:"mac"`
	IP       string  `json:"ip"`
	Hostname string  `json:"hostname"`
	Signal   *int    `json:"signal"`
	RxBytes  *uint64 `json:"rx_bytes"`
	TxBytes  *uint64 `json:"tx_bytes"`
}

// Port describes a physical switch port.
type Port struct {
	Index       uint16   `json:"port_idx"`
	Interface   string   `json:"ifname"`
	Name        string   `json:"name"`
	PoECaps     *uint64  `json:"poe_caps"`
	PoEEnabled  *bool    `json:"port_poe"`
	Up          *bool    `json:"up"`
	Speed       *uint32  `json:"speed"`
	FullDuplex  *bool    `json:"full_duplex"`
	RxBytes     *uint64  `json:"rx_bytes"`
	TxBytes     *uint64  `json:"tx_bytes"`
	PoEPower    *float64 `json:"poe_power"`
	NativeVLAN  *uint16  `json:"native_vlan"`
	TaggedVLANs []uint16 `json:"tagged_vlans"`
	PoEMode     string   `json:"poe_mode"`
}

// Ethernet describes a reported Ethernet interface.
type Ethernet struct {
	MAC      string  `json:"mac"`
	Name     string  `json:"name"`
	NumPorts *uint16 `json:"num_port"`
}

// Uplink describes the device uplink.
type Uplink struct {
	MAC        string  `json:"mac"`
	IP         string  `json:"ip"`
	Name       string  `json:"name"`
	Interface  string  `json:"ifname"`
	Speed      *uint32 `json:"speed"`
	FullDuplex *bool   `json:"full_duplex"`
}

// SwitchCapabilities keeps switch capability namespaces distinct.
type SwitchCapabilities struct {
	FeatureCaps *uint64 `json:"feature_caps"`
	VLANCaps    *uint64 `json:"vlan_caps"`
}
