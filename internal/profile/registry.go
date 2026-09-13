package profile

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"

	"goodkind.io/unifi-go/internal/configmap"
	"goodkind.io/unifi-go/internal/informmodel"
	"goodkind.io/unifi-go/network"
)

// Registry routes each supported family to its injected compiler.
type Registry struct {
	ap       APCompiler
	switches SwitchCompiler
}

// NewRegistry constructs a registry with one compiler per family.
func NewRegistry(ap APCompiler, switches SwitchCompiler) Registry {
	return Registry{ap: ap, switches: switches}
}

// CompileAP routes an access point descriptor to the access point compiler.
func (registry Registry) CompileAP(descriptor DeviceDescriptor, input CompilationInput, config network.APConfig, secrets SecretReader) (Compilation, error) {
	if descriptor.Family != network.FamilyAP {
		return Compilation{}, fmt.Errorf("compile access point: device family is %q", descriptor.Family)
	}
	if registry.ap == nil || !registry.ap.Supports(descriptor) {
		return Compilation{}, fmt.Errorf("compile access point: unsupported device capabilities")
	}
	param, err := registry.ap.Compile(descriptor, input, config, secrets)
	if err != nil {
		slog.Error("access point configuration compilation failed", "error", err)
		return Compilation{}, fmt.Errorf("compile access point: %w", err)
	}
	return param, nil
}

// CompileSwitch routes a switch descriptor to the switch compiler.
func (registry Registry) CompileSwitch(descriptor DeviceDescriptor, input CompilationInput, config network.SwitchConfig, secrets SecretReader) (Compilation, error) {
	if descriptor.Family != network.FamilySwitch {
		return Compilation{}, fmt.Errorf("compile switch: device family is %q", descriptor.Family)
	}
	if registry.switches == nil || !registry.switches.Supports(descriptor) {
		return Compilation{}, fmt.Errorf("compile switch: unsupported device capabilities")
	}
	param, err := registry.switches.Compile(descriptor, input, config, secrets)
	if err != nil {
		slog.Error("switch configuration compilation failed", "error", err)
		return Compilation{}, fmt.Errorf("compile switch: %w", err)
	}
	return param, nil
}

// Decode returns a snapshot containing exactly the selected family's state.
func (registry Registry) Decode(descriptor DeviceDescriptor, report informmodel.Report) (network.DeviceSnapshot, error) {
	snapshot := network.DeviceSnapshot{
		ID: network.DeviceID(report.MAC), Family: descriptor.Family, Model: report.Model,
		Firmware: report.Version, UptimeSeconds: report.Uptime,
		ReportedConfigVersion: network.ConfigVersion(report.ConfigVersion), LastError: report.LastError,
	}
	switch descriptor.Family {
	case network.FamilyAP:
		if registry.ap == nil || !registry.ap.Supports(descriptor) {
			return network.DeviceSnapshot{}, fmt.Errorf("decode access point: unsupported device capabilities")
		}
		decoded, err := registry.ap.Decode(report)
		if err != nil {
			slog.Error("access point snapshot decoding failed", "error", err)
			return network.DeviceSnapshot{}, fmt.Errorf("decode access point: %w", err)
		}
		snapshot.AP = &decoded
	case network.FamilySwitch:
		if registry.switches == nil || !registry.switches.Supports(descriptor) {
			return network.DeviceSnapshot{}, fmt.Errorf("decode switch: unsupported device capabilities")
		}
		decoded, err := registry.switches.Decode(report)
		if err != nil {
			slog.Error("switch snapshot decoding failed", "error", err)
			return network.DeviceSnapshot{}, fmt.Errorf("decode switch: %w", err)
		}
		snapshot.Switch = &decoded
	default:
		return network.DeviceSnapshot{}, fmt.Errorf("decode device: unknown family %q", descriptor.Family)
	}
	return snapshot, nil
}

// CanonicalVersion hashes deterministic, non-transient configuration content.
func CanonicalVersion(param SetParam) (network.ConfigVersion, error) {
	management := canonicalValues(param.Management)
	system := canonicalValues(param.System)
	managementEncoded, err := management.Encode()
	if err != nil {
		slog.Error("management config encoding failed", "error", err)
		return "", fmt.Errorf("encode management config: %w", err)
	}
	systemEncoded, err := system.Encode()
	if err != nil {
		slog.Error("system config encoding failed", "error", err)
		return "", fmt.Errorf("encode system config: %w", err)
	}
	hash := sha256.New()
	writeSection(hash.Write, managementEncoded)
	writeSection(hash.Write, systemEncoded)
	return network.ConfigVersion(hex.EncodeToString(hash.Sum(nil))[:16]), nil
}

func canonicalValues(values configmap.Values) configmap.Values {
	result := values.Clone()
	for _, key := range []string{"cfgversion", "time", "time_ms", "authkey", "inform_url"} {
		result.Delete(key)
	}
	return result
}

func writeSection(write func([]byte) (int, error), value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = write(length[:])
	_, _ = write([]byte(value))
}
