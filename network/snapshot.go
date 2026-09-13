package network

import (
	"net/netip"
	"time"
)

// DeviceSnapshot captures common and family-specific device state.
type DeviceSnapshot struct {
	ID                    DeviceID        `json:"id"`
	Family                DeviceFamily    `json:"family"`
	Model                 string          `json:"model"`
	Firmware              string          `json:"firmware"`
	UptimeSeconds         uint64          `json:"uptime_seconds"`
	ReportedConfigVersion ConfigVersion   `json:"reported_config_version"`
	DesiredConfigVersion  ConfigVersion   `json:"desired_config_version"`
	LastSetParamVersion   ConfigVersion   `json:"last_setparam_version"`
	LastError             string          `json:"last_error"`
	LastInform            time.Time       `json:"last_inform"`
	AP                    *APSnapshot     `json:"ap"`
	Switch                *SwitchSnapshot `json:"switch"`
}

// APSnapshot captures access point state.
type APSnapshot struct {
	Radios  []RadioSnapshot  `json:"radios"`
	Clients []ClientSnapshot `json:"clients"`
	Uplink  *UplinkSnapshot  `json:"uplink"`
}

// RadioSnapshot captures one access point radio.
type RadioSnapshot struct {
	ID          string           `json:"id"`
	Band        RadioBand        `json:"band"`
	Channel     *uint16          `json:"channel"`
	WidthMHz    *ChannelWidthMHz `json:"width_mhz"`
	PowerDBm    *int             `json:"power_dbm"`
	ClientCount *uint32          `json:"client_count"`
}

// ClientSnapshot captures one connected WiFi client.
type ClientSnapshot struct {
	MAC       string     `json:"mac"`
	IP        netip.Addr `json:"ip"`
	Name      string     `json:"name"`
	SSID      string     `json:"ssid"`
	RadioID   string     `json:"radio_id"`
	SignalDBm *int       `json:"signal_dbm"`
	RxBytes   *uint64    `json:"rx_bytes"`
	TxBytes   *uint64    `json:"tx_bytes"`
}

// UplinkSnapshot captures an access point uplink.
type UplinkSnapshot struct {
	MAC       string     `json:"mac"`
	IP        netip.Addr `json:"ip"`
	Name      string     `json:"name"`
	SpeedMbps *uint32    `json:"speed_mbps"`
}

// SwitchSnapshot captures switch state.
type SwitchSnapshot struct {
	Ports []PortSnapshot `json:"ports"`
}

// PortSnapshot captures one switch port.
type PortSnapshot struct {
	Index       uint16   `json:"index"`
	Name        string   `json:"name"`
	Up          *bool    `json:"up"`
	SpeedMbps   *uint32  `json:"speed_mbps"`
	FullDuplex  *bool    `json:"full_duplex"`
	RxBytes     *uint64  `json:"rx_bytes"`
	TxBytes     *uint64  `json:"tx_bytes"`
	NativeVLAN  *VLANID  `json:"native_vlan"`
	TaggedVLANs []VLANID `json:"tagged_vlans"`
	PoEPowerW   *float64 `json:"poe_power_w"`
	PoEMode     PoEMode  `json:"poe_mode"`
}
