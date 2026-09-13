package controller

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"goodkind.io/unifi-go/internal/clock"
	"goodkind.io/unifi-go/internal/configmap"
	"goodkind.io/unifi-go/internal/profile"
	"goodkind.io/unifi-go/network"
)

const previewLifetime = 5 * time.Minute

func (c *Controller) previewControl(request ControlRequest) (*network.ConfigPreview, error) {
	family := network.FamilyAP
	if request.Operation == "preview-switch" {
		family = network.FamilySwitch
	}
	preview, err := c.preview(request.Device, family, request.AP, request.Switch)
	return &preview, err
}

type previewRecord struct {
	fingerprint [sha256.Size]byte
	expires     time.Time
}

type previewSecrets map[network.SecretFile][sha256.Size]byte

func (secrets previewSecrets) ReadSecret(path network.SecretFile) ([]byte, error) {
	data, err := (fileSecrets{}).ReadSecret(path)
	if err != nil {
		return nil, err
	}
	secrets[path] = sha256.Sum256(data)
	return data, nil
}

func (c *Controller) preview(id network.DeviceID, family network.DeviceFamily, ap *network.APConfig, sw *network.SwitchConfig) (network.ConfigPreview, error) {
	mac, err := normalizeMAC(string(id))
	if err != nil {
		return network.ConfigPreview{}, &network.ControlError{Code: network.InvalidDevice}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	device, exists := c.devices[mac]
	if !exists {
		return network.ConfigPreview{}, &network.ControlError{Code: network.NotRegistered}
	}
	compilation, fingerprint, err := c.compilePreviewLocked(device, family, ap, sw)
	if err != nil {
		return network.ConfigPreview{}, err
	}
	input, err := typedCompilationInput(device)
	if err != nil {
		return network.ConfigPreview{}, err
	}
	var result network.ConfigPreview
	countChanges(&result, input.Baseline.Management, compilation.Param.Management)
	countChanges(&result, input.Baseline.System, compilation.Param.System)
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return network.ConfigPreview{}, &network.ControlError{Code: network.RequestFailed}
	}
	result.Token = network.PreviewToken(hex.EncodeToString(random[:]))
	now := clock.Now()
	for token, record := range c.previews {
		if !now.Before(record.expires) {
			delete(c.previews, token)
		}
	}
	c.previews[result.Token] = previewRecord{fingerprint: fingerprint, expires: now.Add(previewLifetime)}
	return result, nil
}

func (c *Controller) compilePreviewLocked(device Device, family network.DeviceFamily, ap *network.APConfig, sw *network.SwitchConfig) (profile.Compilation, [sha256.Size]byte, error) {
	secrets := make(previewSecrets)
	compilation, err := c.compileWithSecretsLocked(device, family, ap, sw, secrets)
	if err != nil {
		return profile.Compilation{}, [sha256.Size]byte{}, err
	}
	descriptor, err := profile.DescribeWithFamily(c.reports[device.MAC], family)
	if err != nil {
		return profile.Compilation{}, [sha256.Size]byte{}, &network.ControlError{Code: network.FamilyMismatch}
	}
	// Report timestamps and client observations do not change the candidate policy.
	input := struct {
		Device       Device                   `json:"device"`
		Capabilities profile.DeviceDescriptor `json:"capabilities"`
		Family       network.DeviceFamily     `json:"family"`
		AP           *network.APConfig        `json:"ap"`
		Switch       *network.SwitchConfig    `json:"switch"`
		Secrets      previewSecrets           `json:"secrets"`
		Version      network.ConfigVersion    `json:"version"`
		Management   configmap.Values         `json:"management"`
		System       configmap.Values         `json:"system"`
	}{Device: device, Capabilities: descriptor, Family: family, AP: ap, Switch: sw, Secrets: secrets, Version: compilation.Param.Version, Management: compilation.Param.Management, System: compilation.Param.System}
	encoded, err := json.Marshal(input)
	if err != nil {
		return profile.Compilation{}, [sha256.Size]byte{}, &network.ControlError{Code: network.EncodingFailed}
	}
	return compilation, sha256.Sum256(encoded), nil
}

func (c *Controller) revalidatePreviewLocked(device Device, family network.DeviceFamily, ap *network.APConfig, sw *network.SwitchConfig, token network.PreviewToken) (profile.Compilation, error) {
	record, exists := c.previews[token]
	if !exists || !clock.Now().Before(record.expires) {
		return profile.Compilation{}, &network.ControlError{Code: network.PreviewStale}
	}
	compilation, fingerprint, err := c.compilePreviewLocked(device, family, ap, sw)
	if err != nil || fingerprint != record.fingerprint || !clock.Now().Before(record.expires) {
		return profile.Compilation{}, &network.ControlError{Code: network.PreviewStale}
	}
	return compilation, nil
}

func countChanges(preview *network.ConfigPreview, before, after configmap.Values) {
	for key, value := range after {
		prior, exists := before[key]
		if !exists {
			preview.Added++
		} else if prior != value {
			preview.Changed++
		}
	}
	for key := range before {
		if _, exists := after[key]; !exists {
			preview.Removed++
		}
	}
}
