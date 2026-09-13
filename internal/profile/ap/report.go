package ap

import (
	"fmt"
	"log/slog"
	"net/netip"

	"goodkind.io/unifi-go/internal/informmodel"
	"goodkind.io/unifi-go/internal/profile"
	"goodkind.io/unifi-go/network"
)

type reportedRadio string

const (
	reportedRadioNG   reportedRadio = "ng"
	reportedRadio2G   reportedRadio = "2g"
	reportedRadio24G  reportedRadio = "2.4ghz"
	reportedRadioNA   reportedRadio = "na"
	reportedRadio5G   reportedRadio = "5g"
	reportedRadio5GHz reportedRadio = "5ghz"
)

func (compiler) Decode(report informmodel.Report) (network.APSnapshot, error) {
	radios := decodeRadios(report)
	clients, err := decodeClients(report)
	if err != nil {
		return network.APSnapshot{}, err
	}
	uplink, err := decodeUplink(report)
	if err != nil {
		return network.APSnapshot{}, err
	}
	return network.APSnapshot{Radios: radios, Clients: clients, Uplink: uplink}, nil
}

func decodeRadios(report informmodel.Report) []network.RadioSnapshot {
	statistics := make(map[string]informmodel.RadioStats, len(report.RadioTableStats))
	for _, item := range report.RadioTableStats {
		statistics[item.Name] = item
	}
	var radios []network.RadioSnapshot
	radioIDs := profile.StableRadioIDs(report.RadioTable)
	for radioIndex, radio := range report.RadioTable {
		identifier := radioIDs[radioIndex]
		item := network.RadioSnapshot{ID: identifier, Band: decodeBand(radio.Radio), Channel: radio.Channel, PowerDBm: radio.TXPower}
		if radio.HT != nil {
			width := network.ChannelWidthMHz(*radio.HT)
			item.WidthMHz = &width
		}
		if stats, exists := statistics[radio.Name]; exists {
			if stats.Channel != nil {
				item.Channel = stats.Channel
			}
			if stats.TXPower != nil {
				item.PowerDBm = stats.TXPower
			}
			if stats.ClientCount != nil {
				item.ClientCount = stats.ClientCount
			}
		}
		applyVAPRadioFallbacks(&item, radio, report.VAPTable)
		radios = append(radios, item)
	}
	return radios
}

func applyVAPRadioFallbacks(item *network.RadioSnapshot, radio informmodel.Radio, vaps []informmodel.VAP) {
	matching := matchingVAPs(radio, vaps)
	if item.Channel == nil {
		item.Channel = consistentUint16(matching, func(vap informmodel.VAP) *uint16 { return vap.Channel })
	}
	if item.WidthMHz == nil {
		width := consistentUint16(matching, func(vap informmodel.VAP) *uint16 {
			if vap.BW == nil {
				return nil
			}
			value := uint16(*vap.BW)
			return &value
		})
		if width != nil {
			value := network.ChannelWidthMHz(*width)
			item.WidthMHz = &value
		}
	}
	if item.PowerDBm == nil {
		item.PowerDBm = consistentInt(matching, func(vap informmodel.VAP) *int { return vap.TXPower })
	}
	if item.ClientCount == nil {
		item.ClientCount = summedClientCount(matching)
	}
}

func matchingVAPs(radio informmodel.Radio, vaps []informmodel.VAP) []informmodel.VAP {
	var matching []informmodel.VAP
	for _, vap := range vaps {
		radioIDMatches := vap.Radio != "" && radio.Radio != "" && vap.Radio == radio.Radio
		radioNameMatches := vap.RadioName != "" && radio.Name != "" && vap.RadioName == radio.Name
		crossNameMatches := vap.Radio != "" && radio.Name != "" && vap.Radio == radio.Name
		if radioIDMatches || radioNameMatches || crossNameMatches {
			matching = append(matching, vap)
		}
	}
	return matching
}

func consistentUint16(vaps []informmodel.VAP, selectValue func(informmodel.VAP) *uint16) *uint16 {
	var result *uint16
	for _, vap := range vaps {
		value := selectValue(vap)
		if value == nil {
			continue
		}
		if result != nil && *result != *value {
			return nil
		}
		copyValue := *value
		result = &copyValue
	}
	return result
}

func consistentInt(vaps []informmodel.VAP, selectValue func(informmodel.VAP) *int) *int {
	var result *int
	for _, vap := range vaps {
		value := selectValue(vap)
		if value == nil {
			continue
		}
		if result != nil && *result != *value {
			return nil
		}
		copyValue := *value
		result = &copyValue
	}
	return result
}

func summedClientCount(vaps []informmodel.VAP) *uint32 {
	if len(vaps) == 0 {
		return nil
	}
	var total uint32
	for _, vap := range vaps {
		if vap.ClientCount == nil {
			return nil
		}
		total += *vap.ClientCount
	}
	return &total
}

func decodeClients(report informmodel.Report) ([]network.ClientSnapshot, error) {
	var clients []network.ClientSnapshot
	for _, vap := range report.VAPTable {
		radioID := clientRadioID(vap, report.RadioTable)
		for _, station := range vap.Stations {
			ip, err := decodeOptionalAddress(station.IP)
			if err != nil {
				slog.Error("station address decoding failed", "error", err)
				return nil, fmt.Errorf("station IP: %w", err)
			}
			clients = append(clients, network.ClientSnapshot{MAC: station.MAC, IP: ip, Name: station.Hostname, SSID: vap.ESSID, RadioID: radioID, SignalDBm: station.Signal, RxBytes: station.RxBytes, TxBytes: station.TxBytes})
		}
	}
	return clients, nil
}

func clientRadioID(vap informmodel.VAP, radios []informmodel.Radio) string {
	identifiers := profile.StableRadioIDs(radios)
	codeCounts := make(map[string]int, len(radios))
	for _, radio := range radios {
		codeCounts[radio.Radio]++
	}
	for index, radio := range radios {
		radioNameMatches := vap.RadioName != "" && vap.RadioName == radio.Name
		crossNameMatches := vap.Radio != "" && vap.Radio == radio.Name
		if radioNameMatches || crossNameMatches {
			return identifiers[index]
		}
		if vap.Radio != "" && vap.Radio == radio.Radio && codeCounts[radio.Radio] == 1 {
			return identifiers[index]
		}
	}
	if vap.RadioName != "" {
		return vap.RadioName
	}
	return vap.Radio
}

func decodeUplink(report informmodel.Report) (*network.UplinkSnapshot, error) {
	if report.Uplink != nil && (report.Uplink.MAC != "" || report.Uplink.IP != "" || report.Uplink.Name != "" || report.Uplink.Speed != nil) {
		uplink := &report.Uplink.Uplink
		ip, err := decodeOptionalAddress(uplink.IP)
		if err != nil {
			slog.Error("uplink address decoding failed", "error", err)
			return nil, fmt.Errorf("uplink IP: %w", err)
		}
		return &network.UplinkSnapshot{MAC: uplink.MAC, IP: ip, Name: uplink.Name, SpeedMbps: uplink.Speed}, nil
	}
	if report.Uplink != nil && report.Uplink.Interface != "" {
		return decodePhysicalUplink(report), nil
	}
	return nil, nil
}

func decodePhysicalUplink(report informmodel.Report) *network.UplinkSnapshot {
	item := network.UplinkSnapshot{Name: report.Uplink.Interface}
	for _, port := range report.PortTable {
		if port.Interface == report.Uplink.Interface || port.Interface == "" && len(report.PortTable) == 1 {
			item.Name = port.Name
			item.SpeedMbps = port.Speed
			return &item
		}
	}
	var soleUp *informmodel.Port
	for index := range report.PortTable {
		port := &report.PortTable[index]
		if port.Interface != "" || port.Up == nil || !*port.Up {
			continue
		}
		if soleUp != nil {
			return &item
		}
		soleUp = port
	}
	if soleUp != nil {
		item.Name = soleUp.Name
		item.SpeedMbps = soleUp.Speed
	}
	return &item
}

func decodeOptionalAddress(value string) (netip.Addr, error) {
	if value == "" {
		return netip.Addr{}, nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		slog.Error("address parsing failed", "error", err)
		return netip.Addr{}, fmt.Errorf("parse address: %w", err)
	}
	return address, nil
}

func decodeBand(value string) network.RadioBand {
	switch reportedRadio(value) {
	case reportedRadioNG, reportedRadio2G, reportedRadio24G:
		return network.Band2GHz
	case reportedRadioNA, reportedRadio5G, reportedRadio5GHz:
		return network.Band5GHz
	default:
		return ""
	}
}
