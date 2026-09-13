package network

import (
	"strings"
	"testing"
)

func vlan(value VLANID) *VLANID {
	return &value
}

func channel(value uint16) *uint16 {
	return &value
}

func dbm(value int) *int {
	return &value
}

func validAPConfig() APConfig {
	return APConfig{
		CountryCode: 840,
		Networks: []WiFiNetwork{{
			Name:    "office",
			Enabled: true,
			VLAN:    vlan(10),
			Bands:   []RadioBand{Band2GHz, Band5GHz},
			Security: WiFiSecurity{
				Mode: WPA2Personal,
				PSK:  SecretFile("/run/secrets/office-psk"),
			},
		}},
		Radios: []RadioConfig{
			{Band: Band2GHz, Enabled: true, WidthMHz: Width20, Power: PowerConfig{Mode: PowerAuto}},
			{Band: Band5GHz, Enabled: true, Channel: channel(36), WidthMHz: Width40, Power: PowerConfig{Mode: PowerExplicit, DBm: dbm(18)}},
		},
	}
}

func TestAPConfigValidateAcceptsValidConfigurations(t *testing.T) {
	tests := map[string]APConfig{
		"dual band": validAPConfig(),
		"no networks": {
			CountryCode: 840,
			Radios:      []RadioConfig{{Band: Band5GHz, Enabled: false, WidthMHz: Width20, Power: PowerConfig{Mode: PowerAuto}}},
		},
	}

	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			if err := config.Validate(); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestAPConfigValidateRejectsInvalidConfigurations(t *testing.T) {
	tests := map[string]struct {
		mutate func(*APConfig)
		path   string
	}{
		"country":                   {func(config *APConfig) { config.CountryCode = 0 }, "country_code"},
		"empty ssid":                {func(config *APConfig) { config.Networks[0].Name = "" }, "networks[0].name"},
		"long ssid":                 {func(config *APConfig) { config.Networks[0].Name = strings.Repeat("x", 33) }, "networks[0].name"},
		"duplicate ssid":            {func(config *APConfig) { config.Networks = append(config.Networks, config.Networks[0]) }, "networks[1].name"},
		"invalid vlan":              {func(config *APConfig) { config.Networks[0].VLAN = vlan(4095) }, "networks[0].vlan"},
		"duplicate network band":    {func(config *APConfig) { config.Networks[0].Bands = append(config.Networks[0].Bands, Band2GHz) }, "networks[0].bands[2]"},
		"missing configured band":   {func(config *APConfig) { config.Networks[0].Bands = append(config.Networks[0].Bands, RadioBand("6ghz")) }, "networks[0].bands[2]"},
		"unknown security":          {func(config *APConfig) { config.Networks[0].Security.Mode = WiFiSecurityMode("open") }, "networks[0].security.mode"},
		"missing secret":            {func(config *APConfig) { config.Networks[0].Security.PSK = "" }, "networks[0].security.psk"},
		"duplicate radio band":      {func(config *APConfig) { config.Radios = append(config.Radios, config.Radios[0]) }, "radios[2].band"},
		"unknown radio band":        {func(config *APConfig) { config.Radios[0].Band = RadioBand("6ghz") }, "radios[0].band"},
		"zero channel":              {func(config *APConfig) { config.Radios[0].Channel = channel(0) }, "radios[0].channel"},
		"invalid width":             {func(config *APConfig) { config.Radios[0].WidthMHz = ChannelWidthMHz(80) }, "radios[0].width_mhz"},
		"unknown power":             {func(config *APConfig) { config.Radios[0].Power.Mode = PowerMode("high") }, "radios[0].power.mode"},
		"incomplete explicit power": {func(config *APConfig) { config.Radios[1].Power.DBm = nil }, "radios[1].power.dbm"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			config := validAPConfig()
			test.mutate(&config)
			err := config.Validate()
			if err == nil || !strings.Contains(err.Error(), test.path) {
				t.Fatalf("Validate() error = %v, want path %q", err, test.path)
			}
		})
	}
}

func validSwitchConfig() SwitchConfig {
	return SwitchConfig{Ports: []SwitchPortConfig{
		{Index: 1, Enabled: true, NativeVLAN: 1, TaggedVLANs: []VLANID{10, 20}, PoE: PoEAuto},
		{Index: 2, Enabled: true, NativeVLAN: 30, PoE: PoEOff},
	}}
}

func TestSwitchConfigValidateAcceptsValidConfigurations(t *testing.T) {
	tests := map[string]SwitchConfig{
		"configured ports": validSwitchConfig(),
		"preserve poe":     {Ports: []SwitchPortConfig{{Index: 1, NativeVLAN: 1}}},
	}

	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			if err := config.Validate(); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestSwitchConfigValidateRejectsInvalidConfigurations(t *testing.T) {
	tests := map[string]struct {
		mutate func(*SwitchConfig)
		path   string
	}{
		"zero index":            {func(config *SwitchConfig) { config.Ports[0].Index = 0 }, "ports[0].index"},
		"duplicate port":        {func(config *SwitchConfig) { config.Ports[1].Index = 1 }, "ports[1].index"},
		"invalid native vlan":   {func(config *SwitchConfig) { config.Ports[0].NativeVLAN = 0 }, "ports[0].native_vlan"},
		"invalid tagged vlan":   {func(config *SwitchConfig) { config.Ports[0].TaggedVLANs[0] = 4095 }, "ports[0].tagged_vlans[0]"},
		"duplicate tagged vlan": {func(config *SwitchConfig) { config.Ports[0].TaggedVLANs[1] = 10 }, "ports[0].tagged_vlans[1]"},
		"native vlan tagged":    {func(config *SwitchConfig) { config.Ports[0].TaggedVLANs[0] = 1 }, "ports[0].tagged_vlans[0]"},
		"unknown poe":           {func(config *SwitchConfig) { config.Ports[0].PoE = PoEMode("24v") }, "ports[0].poe"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			config := validSwitchConfig()
			test.mutate(&config)
			err := config.Validate()
			if err == nil || !strings.Contains(err.Error(), test.path) {
				t.Fatalf("Validate() error = %v, want path %q", err, test.path)
			}
		})
	}
}
