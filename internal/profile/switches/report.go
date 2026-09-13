package switches

import (
	"fmt"
	"slices"

	"goodkind.io/unifi-go/internal/informmodel"
	"goodkind.io/unifi-go/network"
)

func (compiler) Decode(report informmodel.Report) (network.SwitchSnapshot, error) {
	ports := make([]network.PortSnapshot, 0, len(report.PortTable))
	for _, port := range report.PortTable {
		var native *network.VLANID
		if port.NativeVLAN != nil {
			if *port.NativeVLAN < 1 || *port.NativeVLAN > 4094 {
				return network.SwitchSnapshot{}, fmt.Errorf("port %d reports invalid native VLAN", port.Index)
			}
			value := network.VLANID(*port.NativeVLAN)
			native = &value
		}
		var tagged []network.VLANID
		if port.TaggedVLANs != nil {
			tagged = make([]network.VLANID, 0, len(port.TaggedVLANs))
		}
		for _, value := range port.TaggedVLANs {
			vlan := network.VLANID(value)
			if value < 1 || value > 4094 || native != nil && vlan == *native || slices.Contains(tagged, vlan) {
				return network.SwitchSnapshot{}, fmt.Errorf("port %d reports invalid tagged VLAN membership", port.Index)
			}
			tagged = append(tagged, vlan)
		}
		mode := network.PoEMode(port.PoEMode)
		if mode != "" && mode != network.PoEAuto && mode != network.PoEOff {
			return network.SwitchSnapshot{}, fmt.Errorf("port %d reports unsupported PoE mode", port.Index)
		}
		name := port.Name
		if name == "" {
			name = port.Interface
		}
		ports = append(ports, network.PortSnapshot{
			Index: port.Index, Name: name, Up: port.Up, SpeedMbps: port.Speed,
			FullDuplex: port.FullDuplex, RxBytes: port.RxBytes, TxBytes: port.TxBytes,
			NativeVLAN: native, TaggedVLANs: tagged, PoEPowerW: port.PoEPower, PoEMode: mode,
		})
	}
	slices.SortFunc(ports, func(left network.PortSnapshot, right network.PortSnapshot) int {
		return int(left.Index) - int(right.Index)
	})
	return network.SwitchSnapshot{Ports: ports}, nil
}
