package network

// AddWiFiRequest copies one existing WiFi network under a new name and secret.
type AddWiFiRequest struct {
	Name     string     `json:"name"`
	Password SecretFile `json:"password"`
	CopyFrom string     `json:"copy_from"`
}

// SetWiFiRequest replaces one named WiFi resource.
type SetWiFiRequest struct {
	CurrentName string      `json:"current_name"`
	Network     WiFiNetwork `json:"network"`
}

// WiFiNetworkView contains only non-secret desired WiFi policy.
type WiFiNetworkView struct {
	Name         string                     `json:"name"`
	Enabled      Optional[bool]             `json:"enabled,omitzero"`
	VLAN         Optional[VLANID]           `json:"vlan,omitzero"`
	Bands        []RadioBand                `json:"bands"`
	RadioIDs     []RadioID                  `json:"radio_ids"`
	SecurityMode Optional[WiFiSecurityMode] `json:"security_mode,omitzero"`
}
