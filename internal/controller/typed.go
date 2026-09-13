package controller

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"

	"goodkind.io/unifi-go/internal/configmap"
	"goodkind.io/unifi-go/internal/informmodel"
	"goodkind.io/unifi-go/internal/profile"
	"goodkind.io/unifi-go/network"
)

type fileSecrets struct{}

func (c *Controller) recordReport(device Device, payload, body []byte) (Device, error) {
	var report informmodel.Report
	if err := json.Unmarshal(payload, &report); err != nil {
		return device, errors.New("invalid device report")
	}
	report.MAC = device.MAC
	report.PacketVersion = binary.BigEndian.Uint32(body[4:8])
	report.PayloadVersion = binary.BigEndian.Uint32(body[32:36])
	verifiedProtocol := report.PacketVersion <= 1 && report.PayloadVersion == 1
	report.SystemConfig, report.ManagementConfig = verifiedProtocol, verifiedProtocol
	c.reports[device.MAC] = report
	var descriptor profile.DeviceDescriptor
	var err error
	if device.Family == "" {
		descriptor, err = profile.Describe(report)
	} else {
		descriptor, err = profile.DescribeWithFamily(report, device.Family)
	}
	// Ambiguous reports remain available for an explicit Apply family hint.
	if err == nil {
		device.Family, device.Descriptor = descriptor.Family, &descriptor
		c.devices[device.MAC] = device
		if err := c.saveLocked(); err != nil {
			return device, errors.New("cannot persist descriptor")
		}
	}
	return device, nil
}

func (fileSecrets) ReadSecret(path network.SecretFile) ([]byte, error) {
	data, err := os.ReadFile(string(path))
	if err != nil {
		return nil, &network.ControlError{Code: network.FileReadFailed, Field: ""}
	}
	return data, nil
}

func (c *Controller) apply(id network.DeviceID, family network.DeviceFamily, ap *network.APConfig, sw *network.SwitchConfig) (network.ConfigVersion, error) {
	mac, err := normalizeMAC(string(id))
	if err != nil {
		return "", &network.ControlError{Code: network.InvalidDevice, Field: ""}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	device, exists := c.devices[mac]
	if !exists {
		return "", &network.ControlError{Code: network.NotRegistered, Field: ""}
	}
	if device.NextKey != "" {
		return "", &network.ControlError{Code: network.AdoptionPending, Field: ""}
	}
	if device.Family != "" && device.Family != family {
		return "", &network.ControlError{Code: network.FamilyMismatch, Field: ""}
	}
	report, exists := c.reports[mac]
	if !exists {
		return "", &network.ControlError{Code: network.NoReport, Field: ""}
	}
	descriptor, err := profile.DescribeWithFamily(report, family)
	if err != nil {
		return "", &network.ControlError{Code: network.FamilyMismatch, Field: ""}
	}
	input, err := typedCompilationInput(device)
	if err != nil {
		return "", err
	}
	var compilation profile.Compilation
	switch family {
	case network.FamilyAP:
		if ap == nil || sw != nil {
			return "", &network.ControlError{Code: network.InvalidConfig, Field: ""}
		}
		compilation, err = c.registry.CompileAP(descriptor, input, *ap, fileSecrets{})
	case network.FamilySwitch:
		if sw == nil || ap != nil {
			return "", &network.ControlError{Code: network.InvalidConfig, Field: ""}
		}
		compilation, err = c.registry.CompileSwitch(descriptor, input, *sw, fileSecrets{})
	default:
		return "", &network.ControlError{Code: network.FamilyMismatch, Field: ""}
	}
	if err != nil {
		return "", compilerFailure(err)
	}
	param := compilation.Param
	command, err := c.typedReply(&param, device)
	if err != nil {
		return "", err
	}
	previous := device
	if ap != nil && ap.SSH.Present && ap.SSH.Value.Password.Present || sw != nil && sw.SSH.Present && sw.SSH.Value.Password.Present {
		username, passwordHash := param.System["users.1.name"], param.System["users.1.password"]
		if username == "" || !strings.HasPrefix(passwordHash, "$6$") {
			return "", &network.ControlError{Code: network.EncodingFailed, Field: ""}
		}
		device.SSHUsername, device.SSHPasswordHash = username, passwordHash
		device.SSHPassword = ""
	}
	device.Family, device.Descriptor = family, &descriptor
	device.DesiredAP, device.DesiredSwitch, device.DesiredVersion = compilation.AP, compilation.Switch, param.Version
	device.LastSetParam = &command
	device.Baseline = &ConfigurationBaseline{
		SchemaVersion: baselineSchemaVersion, TypedReady: true, Bindings: profile.CloneBindings(compilation.Bindings),
		Config: network.Config{Version: param.Version, Management: command.ManagementConfig, System: command.SystemConfig},
	}
	c.devices[mac] = device
	if err := c.saveLocked(); err != nil {
		c.devices[mac] = previous
		return "", &network.ControlError{Code: network.PersistenceFailed, Field: ""}
	}
	c.queues[mac] = append(c.queues[mac], command)
	return param.Version, nil
}

func (c *Controller) snapshotLocked(device Device) (network.DeviceSnapshot, error) {
	snapshot := network.DeviceSnapshot{ID: network.DeviceID(device.MAC), Family: device.Family, DesiredConfigVersion: device.DesiredVersion}
	if device.LastSetParam != nil {
		snapshot.LastSetParamVersion = network.ConfigVersion(device.LastSetParam.ConfigVersion)
	}
	if device.Descriptor != nil {
		snapshot.Model, snapshot.Firmware = device.Descriptor.Model, device.Descriptor.Firmware
	}
	if report, exists := c.reports[device.MAC]; exists && device.Family != "" {
		descriptor, err := profile.DescribeWithFamily(report, device.Family)
		if err != nil {
			return snapshot, &network.ControlError{Code: network.FamilyMismatch, Field: ""}
		}
		snapshot, err = c.registry.Decode(descriptor, report)
		if err != nil {
			return snapshot, &network.ControlError{Code: network.ObservationUnavailable, Field: ""}
		}
		snapshot.LastInform = c.status[device.MAC].LastInform
		snapshot.DesiredConfigVersion = device.DesiredVersion
		if device.LastSetParam != nil {
			snapshot.LastSetParamVersion = network.ConfigVersion(device.LastSetParam.ConfigVersion)
		}
		// Device error text may echo credential material.
		snapshot.LastError = safeDeviceError(snapshot.LastError)
		return snapshot, nil
	}
	switch device.Family {
	case network.FamilyAP:
		snapshot.AP = &network.APSnapshot{}
	case network.FamilySwitch:
		snapshot.Switch = &network.SwitchSnapshot{}
	}
	return snapshot, nil
}

func (c *Controller) deviceSnapshot(id network.DeviceID) (network.DeviceSnapshot, error) {
	mac, err := normalizeMAC(string(id))
	if err != nil {
		return network.DeviceSnapshot{}, &network.ControlError{Code: network.InvalidDevice, Field: ""}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	device, exists := c.devices[mac]
	if !exists {
		return network.DeviceSnapshot{}, &network.ControlError{Code: network.NotRegistered, Field: ""}
	}
	return c.snapshotLocked(device)
}

func safeDeviceError(value string) string {
	if value != "" {
		return "device reported an error"
	}
	return ""
}

func compilerFailure(err error) *network.ControlError {
	failure := &network.ControlError{Code: network.InvalidConfig, Field: ""}
	if typed, ok := errors.AsType[*network.ControlError](err); ok {
		failure.Code = typed.Code
		failure.Field = typed.Field
	}
	if failure.Field != "" {
		return failure
	}
	for cause := err; cause != nil; cause = errors.Unwrap(cause) {
		field, _, found := strings.Cut(cause.Error(), ":")
		candidate := network.ControlError{Code: failure.Code, Field: field}
		if found && candidate.Error() == string(failure.Code)+": "+field {
			failure.Field = field
			break
		}
	}
	return failure
}

func (c *Controller) deviceSnapshots() ([]network.DeviceSnapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	snapshots := make([]network.DeviceSnapshot, 0, len(c.devices))
	for _, device := range c.devices {
		snapshot, err := c.snapshotLocked(device)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, snapshot)
	}
	sort.Slice(snapshots, func(i, j int) bool { return snapshots[i].ID < snapshots[j].ID })
	return snapshots, nil
}

func typedCompilationInput(device Device) (profile.CompilationInput, error) {
	if device.Baseline == nil {
		return profile.CompilationInput{}, &network.ControlError{Code: network.BaselineRequired}
	}
	if !device.Baseline.TypedReady || device.Baseline.SchemaVersion != baselineSchemaVersion {
		return profile.CompilationInput{}, &network.ControlError{Code: network.BaselineUnusable}
	}
	baselineManagement, err := configmap.Parse(device.Baseline.Config.Management)
	if err != nil {
		return profile.CompilationInput{}, &network.ControlError{Code: network.BaselineUnusable}
	}
	baselineSystem, err := configmap.Parse(device.Baseline.Config.System)
	if err != nil {
		return profile.CompilationInput{}, &network.ControlError{Code: network.BaselineUnusable}
	}
	input := profile.CompilationInput{Baseline: profile.SetParam{Version: device.Baseline.Config.Version, Management: baselineManagement, System: baselineSystem}, AP: device.DesiredAP, Switch: device.DesiredSwitch, Bindings: device.Baseline.Bindings}

	return input, nil
}

func (c *Controller) typedReply(param *profile.SetParam, device Device) (Reply, error) {
	version, err := profile.CanonicalVersion(*param)
	if err != nil {
		return Reply{}, &network.ControlError{Code: network.EncodingFailed}
	}
	param.Version = version
	management := param.Management.Clone()
	management["authkey"], management["inform_url"], management["cfgversion"] = device.Key, c.advertise, string(param.Version)
	managementEncoded, err := management.Encode()
	if err != nil {
		return Reply{}, &network.ControlError{Code: network.EncodingFailed, Field: ""}
	}
	systemEncoded, err := param.System.Encode()
	if err != nil {
		return Reply{}, &network.ControlError{Code: network.EncodingFailed, Field: ""}
	}
	command := Reply{Type: ReplySetparam, ConfigVersion: string(param.Version), ManagementConfig: managementEncoded, SystemConfig: systemEncoded, Command: "", Key: "", URI: "", Interval: 0, BlockedStations: "", ServerTime: 0, Parameters: nil}

	return command, nil
}
