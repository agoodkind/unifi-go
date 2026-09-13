package controller

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"maps"
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

func (c *Controller) apply(id network.DeviceID, family network.DeviceFamily, ap *network.APConfig, sw *network.SwitchConfig, token network.PreviewToken) (network.ConfigVersion, error) {
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
	var compilation profile.Compilation
	if token != "" {
		compilation, err = c.revalidatePreviewLocked(device, family, ap, sw, token)
	} else {
		compilation, err = c.compileLocked(device, family, ap, sw)
	}
	if err != nil {
		return "", err
	}
	version, err := c.commitCompiledLocked(device, compilation)
	if err == nil && token != "" {
		delete(c.previews, token)
	}
	return version, err
}

func (c *Controller) compileLocked(device Device, family network.DeviceFamily, ap *network.APConfig, sw *network.SwitchConfig) (profile.Compilation, error) {
	return c.compileWithSecretsLocked(device, family, ap, sw, fileSecrets{})
}

func (c *Controller) compileWithSecretsLocked(device Device, family network.DeviceFamily, ap *network.APConfig, sw *network.SwitchConfig, secrets profile.SecretReader) (profile.Compilation, error) {
	if device.NextKey != "" {
		return profile.Compilation{}, &network.ControlError{Code: network.AdoptionPending, Field: ""}
	}
	if device.Family != "" && device.Family != family {
		return profile.Compilation{}, &network.ControlError{Code: network.FamilyMismatch, Field: ""}
	}
	report, exists := c.reports[device.MAC]
	if !exists {
		return profile.Compilation{}, &network.ControlError{Code: network.NoReport, Field: ""}
	}
	descriptor, err := profile.DescribeWithFamily(report, family)
	if err != nil {
		return profile.Compilation{}, &network.ControlError{Code: network.FamilyMismatch, Field: ""}
	}
	input, err := typedCompilationInput(device)
	if err != nil {
		return profile.Compilation{}, err
	}
	if c.awaiting[device.MAC] != "" || len(c.queues[device.MAC]) != 0 {
		return profile.Compilation{}, &network.ControlError{Code: network.ConfigurationPending}
	}
	var compilation profile.Compilation
	switch family {
	case network.FamilyAP:
		if ap == nil || sw != nil {
			return profile.Compilation{}, &network.ControlError{Code: network.InvalidConfig, Field: ""}
		}
		compilation, err = c.registry.CompileAP(descriptor, input, *ap, secrets)
	case network.FamilySwitch:
		if sw == nil || ap != nil {
			return profile.Compilation{}, &network.ControlError{Code: network.InvalidConfig, Field: ""}
		}
		compilation, err = c.registry.CompileSwitch(descriptor, input, *sw, secrets)
	default:
		return profile.Compilation{}, &network.ControlError{Code: network.FamilyMismatch, Field: ""}
	}
	if err != nil {
		return profile.Compilation{}, compilerFailure(err)
	}
	if hasSSHPassword(ap, sw) && (compilation.Param.System["users.1.name"] == "" || !strings.HasPrefix(compilation.Param.System["users.1.password"], "$6$")) {
		return profile.Compilation{}, &network.ControlError{Code: network.EncodingFailed}
	}
	if _, err := c.typedReply(&compilation.Param, device); err != nil {
		return profile.Compilation{}, err
	}
	return compilation, nil
}

func (c *Controller) commitCompiledLocked(device Device, compilation profile.Compilation) (network.ConfigVersion, error) {
	param := compilation.Param
	command, err := c.typedReply(&param, device)
	if err != nil {
		return "", err
	}
	previous := c.devices[device.MAC]
	ap := compilation.AP
	username, passwordHash := param.System["users.1.name"], param.System["users.1.password"]
	if hasSSHPassword(compilation.AP, compilation.Switch) && username != "" && strings.HasPrefix(passwordHash, "$6$") {
		device.SSHUsername, device.SSHPasswordHash = username, passwordHash
		device.SSHPassword = ""
	}
	family := network.FamilySwitch
	if ap != nil {
		family = network.FamilyAP
	}
	descriptor, err := profile.DescribeWithFamily(c.reports[device.MAC], family)
	if err != nil {
		return "", &network.ControlError{Code: network.FamilyMismatch}
	}
	device.Family, device.Descriptor = family, &descriptor
	device.DesiredAP, device.DesiredSwitch, device.DesiredVersion = compilation.AP, compilation.Switch, param.Version
	device.LastSetParam = &command
	device.Baseline = &ConfigurationBaseline{
		SchemaVersion: baselineSchemaVersion, TypedReady: true, Bindings: profile.CloneBindings(compilation.Bindings),
		Config: network.Config{Version: param.Version, Management: command.ManagementConfig, System: command.SystemConfig},
	}
	c.devices[device.MAC] = device
	if err := c.saveLocked(); err != nil {
		c.devices[device.MAC] = previous
		return "", &network.ControlError{Code: network.PersistenceFailed, Field: ""}
	}
	if c.reports[device.MAC].ConfigVersion != string(param.Version) {
		c.queues[device.MAC] = append(c.queues[device.MAC], command)
		c.awaiting[device.MAC] = param.Version
	}
	return param.Version, nil
}

func hasSSHPassword(ap *network.APConfig, sw *network.SwitchConfig) bool {
	return ap != nil && ap.SSH.Present && ap.SSH.Value.Password.Present || sw != nil && sw.SSH.Present && sw.SSH.Value.Password.Present
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
	input := profile.CompilationInput{Baseline: profile.SetParam{Version: device.Baseline.Config.Version, Management: baselineManagement, System: baselineSystem}, AP: nil, Switch: nil, Bindings: profile.CloneBindings(device.Baseline.Bindings), WiFiCopies: cloneWiFiCopies(device.wifiCopies)}
	if device.DesiredAP != nil {
		cloned := profile.MergeAP(device.DesiredAP, network.APConfig{})
		input.AP = &cloned
	}
	if device.DesiredSwitch != nil {
		cloned := profile.MergeSwitch(device.DesiredSwitch, network.SwitchConfig{})
		input.Switch = &cloned
	}

	return input, nil
}

func cloneWiFiCopies(copies map[string]string) map[string]string {
	return maps.Clone(copies)
}

func (c *Controller) typedReply(param *profile.SetParam, device Device) (Reply, error) {
	version, err := profile.CanonicalVersion(*param)
	if err != nil {
		return Reply{}, &network.ControlError{Code: network.EncodingFailed}
	}
	param.Version = version
	management := param.Management.Clone()
	management["authkey"], management["inform_url"], management["cfgversion"] = device.Key, c.advertise, string(param.Version)
	param.Management = management
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
