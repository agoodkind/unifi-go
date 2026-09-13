package network

import (
	"strings"
	"testing"
)

func validAPConfig() APConfig {
	return APConfig{
		CountryCode: Supplied(uint16(840)),
		Networks: Supplied([]WiFiNetwork{{
			Name: "office", Enabled: Supplied(true), VLAN: Supplied(VLANID(10)),
			Bands:         Supplied([]RadioBand{Band2GHz, Band5GHz}),
			BSSTransition: Supplied(BSSTransitionEnabled),
			Security: Supplied(WiFiSecurity{
				Mode: Supplied(WPA2Personal),
				PSK:  Supplied(SecretFile("/run/secrets/office-psk")),
			}),
		}}),
		Radios: Supplied([]RadioConfig{
			{Band: Band2GHz, Enabled: Supplied(true), Channel: Cleared[uint16](), WidthMHz: Supplied(Width20), Power: Supplied(PowerConfig{Mode: Supplied(PowerAuto)})},
			{Band: Band5GHz, Enabled: Supplied(true), Channel: Supplied(uint16(36)), WidthMHz: Supplied(Width40), Power: Supplied(PowerConfig{Mode: Supplied(PowerExplicit), DBm: Supplied(18)})},
		}),
	}
}

func TestAPConfigValidateAcceptsValidConfigurations(t *testing.T) {
	tests := map[string]APConfig{
		"dual band": validAPConfig(),
		"no networks": {
			CountryCode: Supplied(uint16(840)),
			Networks:    Supplied([]WiFiNetwork{}),
			Radios:      Supplied([]RadioConfig{{Band: Band5GHz, Enabled: Supplied(false), Channel: Cleared[uint16](), WidthMHz: Supplied(Width20), Power: Supplied(PowerConfig{Mode: Supplied(PowerAuto)})}}),
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
		"country":    {func(config *APConfig) { config.CountryCode = Supplied(uint16(0)) }, "country_code"},
		"empty ssid": {func(config *APConfig) { config.Networks.Value[0].Name = "" }, "networks[0].name"},
		"long ssid":  {func(config *APConfig) { config.Networks.Value[0].Name = strings.Repeat("x", 33) }, "networks[0].name"},
		"duplicate ssid": {func(config *APConfig) {
			config.Networks.Value = append(config.Networks.Value, config.Networks.Value[0])
		}, "networks[1].name"},
		"invalid vlan": {func(config *APConfig) { config.Networks.Value[0].VLAN = Supplied(VLANID(4095)) }, "networks[0].vlan"},
		"duplicate network band": {func(config *APConfig) {
			config.Networks.Value[0].Bands.Value = append(config.Networks.Value[0].Bands.Value, Band2GHz)
		}, "networks[0].bands[2]"},
		"missing configured band": {func(config *APConfig) {
			config.Networks.Value[0].Bands.Value = append(config.Networks.Value[0].Bands.Value, RadioBand("6ghz"))
		}, "networks[0].bands[2]"},
		"unknown security": {func(config *APConfig) {
			config.Networks.Value[0].Security.Value.Mode = Supplied(WiFiSecurityMode("open"))
		}, "networks[0].security.mode"},
		"missing secret": {func(config *APConfig) { config.Networks.Value[0].Security.Value.PSK = Supplied(SecretFile("")) }, "networks[0].security.psk"},
		"unknown bss transition": {func(config *APConfig) {
			config.Networks.Value[0].BSSTransition = Supplied(BSSTransitionMode("automatic"))
		}, "networks[0].bss_transition"},
		"duplicate radio band":      {func(config *APConfig) { config.Radios.Value = append(config.Radios.Value, config.Radios.Value[0]) }, "radios[2].band"},
		"unknown radio band":        {func(config *APConfig) { config.Radios.Value[0].Band = RadioBand("6ghz") }, "radios[0].band"},
		"zero channel":              {func(config *APConfig) { config.Radios.Value[0].Channel = Supplied(uint16(0)) }, "radios[0].channel"},
		"invalid width":             {func(config *APConfig) { config.Radios.Value[0].WidthMHz = Supplied(ChannelWidthMHz(80)) }, "radios[0].width_mhz"},
		"unknown power":             {func(config *APConfig) { config.Radios.Value[0].Power.Value.Mode = Supplied(PowerMode("high")) }, "radios[0].power.mode"},
		"incomplete explicit power": {func(config *APConfig) { config.Radios.Value[1].Power.Value.DBm = Optional[int]{} }, "radios[1].power.dbm"},
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
	return SwitchConfig{Ports: Supplied([]SwitchPortConfig{
		{Index: 1, Enabled: Supplied(true), NativeVLAN: Supplied(VLANID(1)), TaggedVLANs: Supplied([]VLANID{10, 20}), PoE: Supplied(PoEAuto)},
		{Index: 2, Enabled: Supplied(true), NativeVLAN: Supplied(VLANID(30)), TaggedVLANs: Supplied([]VLANID{}), PoE: Supplied(PoEOff)},
	})}
}

func TestSwitchConfigValidateAcceptsValidConfigurations(t *testing.T) {
	tests := map[string]SwitchConfig{
		"configured ports": validSwitchConfig(),
		"preserve poe":     {Ports: Supplied([]SwitchPortConfig{{Index: 1, NativeVLAN: Supplied(VLANID(1))}})},
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
		"zero index":            {func(config *SwitchConfig) { config.Ports.Value[0].Index = 0 }, "ports[0].index"},
		"duplicate port":        {func(config *SwitchConfig) { config.Ports.Value[1].Index = 1 }, "ports[1].index"},
		"invalid native vlan":   {func(config *SwitchConfig) { config.Ports.Value[0].NativeVLAN = Supplied(VLANID(0)) }, "ports[0].native_vlan"},
		"invalid tagged vlan":   {func(config *SwitchConfig) { config.Ports.Value[0].TaggedVLANs.Value[0] = 4095 }, "ports[0].tagged_vlans[0]"},
		"duplicate tagged vlan": {func(config *SwitchConfig) { config.Ports.Value[0].TaggedVLANs.Value[1] = 10 }, "ports[0].tagged_vlans[1]"},
		"native vlan tagged":    {func(config *SwitchConfig) { config.Ports.Value[0].TaggedVLANs.Value[0] = 1 }, "ports[0].tagged_vlans[0]"},
		"unknown poe":           {func(config *SwitchConfig) { config.Ports.Value[0].PoE = Supplied(PoEMode("24v")) }, "ports[0].poe"},
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
