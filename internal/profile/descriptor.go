package profile

import (
	"fmt"

	"goodkind.io/unifi-go/internal/informmodel"
	"goodkind.io/unifi-go/network"
)

const (
	poe8023AFCapability           uint64 = 1
	poe8023ATCapability           uint64 = 2
	poePassive24Capability        uint64 = 4
	poePassthroughCapability      uint64 = 8
	poeFixedPassthroughCapability uint64 = 16
	poe8023BTType3Capability      uint64 = 32
	poe8023BTType4Capability      uint64 = 64
	poeNegotiatedCapabilities            = poe8023AFCapability | poe8023ATCapability |
		poe8023BTType3Capability | poe8023BTType4Capability
	poeOutputCapabilities = poeNegotiatedCapabilities | poePassive24Capability |
		poePassthroughCapability | poeFixedPassthroughCapability
)

type reportedType string

const (
	reportedTypeAP     reportedType = "uap"
	reportedTypeSwitch reportedType = "usw"
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

// Describe derives a descriptor from explicit report evidence.
func Describe(report informmodel.Report) (DeviceDescriptor, error) {
	return DescribeWithFamily(report, "")
}

// DescribeWithFamily uses familyHint only when the report has no family evidence.
func DescribeWithFamily(report informmodel.Report, familyHint network.DeviceFamily) (DeviceDescriptor, error) {
	family, err := reportedFamily(report, familyHint)
	if err != nil {
		return DeviceDescriptor{}, err
	}
	descriptor := DeviceDescriptor{
		Family:          family,
		Model:           report.Model,
		Firmware:        report.Version,
		UplinkInterface: "",
		Protocol: ProtocolCapabilities{
			PacketVersion:    report.PacketVersion,
			PayloadVersion:   report.PayloadVersion,
			SystemConfig:     report.SystemConfig,
			ManagementConfig: report.ManagementConfig,
		},
		Radios: nil,
		Ports:  nil,
	}
	if report.Uplink != nil {
		descriptor.UplinkInterface = report.Uplink.Interface
	}
	for radioIndex, radio := range report.RadioTable {
		identifier := radio.Radio
		if identifier == "" {
			identifier = radio.Name
		}
		if identifier == "" {
			identifier = fmt.Sprintf("radio-%d", radioIndex)
		}
		capability := RadioCapability{
			ID:          identifier,
			Interface:   radio.Name,
			Band:        radioBand(radio.Radio),
			Channels:    append([]uint16(nil), radio.Channels...),
			Widths:      nil,
			MinPowerDBm: radio.MinTXPower, MaxPowerDBm: radio.MaxTXPower,
		}
		for _, width := range radio.Widths {
			capability.Widths = append(capability.Widths, network.ChannelWidthMHz(width))
		}
		descriptor.Radios = append(descriptor.Radios, capability)
	}
	ports := reportedPorts(report, family)
	soleUpIndex := soleUpPortIndex(ports)
	for portIndex, port := range ports {
		interfaceName := port.Interface
		if interfaceName == "" && len(ports) == 1 && report.Uplink != nil {
			interfaceName = report.Uplink.Interface
		}
		if interfaceName == "" && portIndex == soleUpIndex && report.Uplink != nil {
			interfaceName = report.Uplink.Interface
		}
		capability := PortCapability{
			Index: port.Index, Interface: interfaceName, VLAN: nil, PoEModes: nil,
		}
		if report.SwitchCaps != nil && report.SwitchCaps.VLANCaps != nil {
			supported := *report.SwitchCaps.VLANCaps != 0
			capability.VLAN = &supported
		}
		if port.PoECaps != nil {
			if *port.PoECaps&poeNegotiatedCapabilities != 0 {
				capability.PoEModes = append(capability.PoEModes, network.PoEAuto)
			}
			if *port.PoECaps&poeOutputCapabilities != 0 {
				capability.PoEModes = append(capability.PoEModes, network.PoEOff)
			}
		}
		descriptor.Ports = append(descriptor.Ports, capability)
	}
	return descriptor, nil
}

func reportedPorts(report informmodel.Report, family network.DeviceFamily) []informmodel.Port {
	if family != network.FamilyAP || len(report.EthernetTable.Entries) == 0 {
		return report.PortTable
	}
	ports := make([]informmodel.Port, 0, len(report.EthernetTable.Entries))
	for portIndex, ethernet := range report.EthernetTable.Entries {
		ports = append(ports, informmodel.Port{
			Index: uint16(portIndex + 1), Interface: ethernet.Name, Name: "", PoECaps: nil,
			PoEEnabled: nil, Up: nil, Speed: nil, FullDuplex: nil, RxBytes: nil,
			TxBytes: nil, PoEPower: nil, NativeVLAN: nil, TaggedVLANs: nil, PoEMode: "",
		})
	}
	return ports
}

func soleUpPortIndex(ports []informmodel.Port) int {
	result := -1
	for index, port := range ports {
		if port.Up == nil || !*port.Up {
			continue
		}
		if result != -1 {
			return -2
		}
		result = index
	}
	return result
}

func reportedFamily(report informmodel.Report, familyHint network.DeviceFamily) (network.DeviceFamily, error) {
	var family network.DeviceFamily
	switch reportedType(report.Type) {
	case reportedTypeAP:
		family = network.FamilyAP
	case reportedTypeSwitch:
		family = network.FamilySwitch
	case "":
		if len(report.RadioTable) > 0 && len(report.PortTable) == 0 {
			family = network.FamilyAP
		}
		if len(report.PortTable) > 0 && len(report.RadioTable) == 0 {
			family = network.FamilySwitch
		}
	default:
		return "", fmt.Errorf("describe device: unknown reported type %q", report.Type)
	}
	if family == "" {
		family = familyHint
	}
	if family != network.FamilyAP && family != network.FamilySwitch {
		return "", fmt.Errorf("describe device: family is not reported or unambiguous")
	}
	if familyHint != "" && familyHint != family {
		return "", fmt.Errorf("describe device: family hint %q conflicts with report family %q", familyHint, family)
	}
	return family, nil
}

func radioBand(value string) network.RadioBand {
	switch reportedRadio(value) {
	case reportedRadioNG, reportedRadio2G, reportedRadio24G:
		return network.Band2GHz
	case reportedRadioNA, reportedRadio5G, reportedRadio5GHz:
		return network.Band5GHz
	default:
		return ""
	}
}
