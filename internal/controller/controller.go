// Package controller serves encrypted UniFi informs and a local control API.
package controller

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/jamesbraid/unifi-emu/inform"

	"goodkind.io/unifi-go/internal/clock"
	"goodkind.io/unifi-go/internal/informmodel"
	"goodkind.io/unifi-go/internal/profile"
	"goodkind.io/unifi-go/network"
)

// Device is the persisted identity and configuration of one managed device.
type Device struct {
	Family          network.DeviceFamily      `json:"family,omitempty"`
	Descriptor      *profile.DeviceDescriptor `json:"descriptor,omitempty"`
	DesiredAP       *network.APConfig         `json:"desired_ap,omitempty"`
	DesiredSwitch   *network.SwitchConfig     `json:"desired_switch,omitempty"`
	DesiredVersion  network.ConfigVersion     `json:"desired_version,omitempty"`
	Baseline        *ConfigurationBaseline    `json:"baseline,omitempty"`
	MAC             string                    `json:"mac"`
	Key             string                    `json:"key"`
	LastSetParam    *Reply                    `json:"last_setparam,omitempty"`
	SSHUsername     string                    `json:"ssh_username,omitempty"`
	SSHPassword     string                    `json:"ssh_password,omitempty"`
	SSHPasswordHash string                    `json:"ssh_password_hash,omitempty"`
	NextKey         string                    `json:"next_key,omitempty"`
}

// Status contains only non-secret operational fields.
type Status struct {
	MAC                   string                `json:"mac"`
	LastInform            time.Time             `json:"last_inform"`
	ReportedConfigVersion network.ConfigVersion `json:"reported_config_version"`
	DesiredConfigVersion  network.ConfigVersion `json:"desired_config_version"`
	LastSetParamVersion   network.ConfigVersion `json:"last_setparam_version"`
	Model                 string                `json:"model,omitempty"`
	Firmware              string                `json:"firmware,omitempty"`
	IP                    string                `json:"ip,omitempty"`
	IPv6                  []string              `json:"ipv6,omitempty"`
	DeviceState           int                   `json:"state,omitempty"`
	InformURL             string                `json:"inform_url,omitempty"`
	LastError             string                `json:"last_error,omitempty"`
	Pending               int                   `json:"pending"`
}

// InformReport is the device state read from each inform request.
type InformReport struct {
	ConfigVersion string   `json:"cfgversion"`
	Model         string   `json:"model"`
	Firmware      string   `json:"version"`
	IP            string   `json:"ip"`
	IPv6          []string `json:"ipv6"`
	State         int      `json:"state"`
	InformURL     string   `json:"inform_url"`
	LastError     string   `json:"last_error"`
}

// Controller owns persistent devices and an in-memory command queue.
type Controller struct {
	registry  profile.Registry
	reports   map[string]informmodel.Report
	mu        sync.Mutex
	stateFile string
	advertise string
	devices   map[string]Device
	queues    map[string][]Reply
	awaiting  map[string]network.ConfigVersion
	previews  map[network.PreviewToken]previewRecord
	status    map[string]Status
}

// Open loads devices from a JSON file, creating an empty state when it is absent.
func Open(stateFile, advertise string, registries ...profile.Registry) (*Controller, error) {
	u, err := url.Parse(advertise)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.Path != "/inform" || u.User != nil {
		return nil, errors.New("advertise must be an HTTP URL ending in /inform")
	}
	c := &Controller{mu: sync.Mutex{}, stateFile: stateFile, advertise: advertise, devices: make(map[string]Device), queues: make(map[string][]Reply), status: make(map[string]Status), reports: make(map[string]informmodel.Report), registry: profile.Registry{}, awaiting: make(map[string]network.ConfigVersion), previews: make(map[network.PreviewToken]previewRecord)}
	if len(registries) > 0 {
		c.registry = registries[0]
	}
	data, err := os.ReadFile(stateFile)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, fault("read state", err)
	}
	var devices []Device
	if err := json.Unmarshal(data, &devices); err != nil {
		return nil, fault("decode state", err)
	}
	var legacyDevices []struct {
		Config *Reply `json:"config,omitempty"`
	}
	if err := json.Unmarshal(data, &legacyDevices); err != nil {
		return nil, fault("decode legacy state", err)
	}
	for index, device := range devices {
		if device.LastSetParam == nil && index < len(legacyDevices) {
			device.LastSetParam = legacyDevices[index].Config
		}
		if device.Baseline == nil && device.LastSetParam != nil {
			baseline, baselineErr := baselineFromLegacy(device)
			if baselineErr == nil {
				device.Baseline = baseline
			}
		}
		mac, err := normalizeMAC(device.MAC)
		if err != nil {
			return nil, err
		}
		if _, err := inform.ParseKey(device.Key); err != nil {
			return nil, errors.New("state contains an invalid inform key")
		}
		device.MAC = mac
		c.devices[mac] = device
	}
	return c, nil
}

func normalizeMAC(value string) (string, error) {
	mac, err := net.ParseMAC(value)
	if err != nil || len(mac) != 6 {
		return "", errors.New("a six-byte device MAC address is required")
	}
	return mac.String(), nil
}

func (c *Controller) saveLocked() error {
	slog.Debug("save device state", "devices", len(c.devices))
	devices := make([]Device, 0, len(c.devices))
	for _, device := range c.devices {
		devices = append(devices, device)
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].MAC < devices[j].MAC })
	data, err := json.MarshalIndent(devices, "", "  ")
	if err != nil {
		return fault("encode state", err)
	}
	if err := os.MkdirAll(filepath.Dir(c.stateFile), 0o700); err != nil {
		return fault("create state directory", err)
	}
	return replaceState(c.stateFile, data)
}

func replaceState(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".devices-*")
	if err != nil {
		return errors.New("cannot create state temporary file")
	}
	name := temporary.Name()
	defer func() {
		if err := os.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Error("cannot remove state temporary file", "err", errors.New("temporary file removal failed"))
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		if closeErr := temporary.Close(); closeErr != nil {
			slog.Error("cannot close state temporary file", "err", errors.New("temporary file close failed"))
		}
		return errors.New("cannot secure state temporary file")
	}
	if _, err := temporary.Write(data); err != nil {
		if closeErr := temporary.Close(); closeErr != nil {
			slog.Error("cannot close state temporary file", "err", errors.New("temporary file close failed"))
		}
		return errors.New("cannot write state temporary file")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("cannot close state temporary file")
	}
	if err := os.Rename(name, path); err != nil {
		return errors.New("cannot replace state file")
	}
	return nil
}

// Register persists an existing key without replacing an existing device's configuration.
func (c *Controller) Register(mac, key string) error {
	mac, err := normalizeMAC(mac)
	if err != nil {
		return err
	}
	key = strings.TrimSpace(key)
	if _, err := inform.ParseKey(key); err != nil {
		return errors.New("key file must contain a 32-character hexadecimal inform key")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	device, existed := c.devices[mac]
	previous := device
	device.MAC, device.Key = mac, key
	c.devices[mac] = device
	if err := c.saveLocked(); err != nil {
		if existed {
			c.devices[mac] = previous
		} else {
			delete(c.devices, mac)
		}
		return err
	}
	return nil
}

// Adopt queues captured configuration and optionally installs generated SSH credentials.
func (c *Controller) Adopt(mac string, template Reply, setupSSH bool) error {
	mac, err := normalizeMAC(mac)
	if err != nil {
		return err
	}
	if template.Type != ReplySetparam {
		return errors.New("adoption template must be a setparam reply")
	}
	if template.SystemConfig == "" {
		return errors.New("adoption template requires system_cfg")
	}
	if template.ManagementConfig == "" {
		return errors.New("adoption template requires mgmt_cfg")
	}
	systemConfig := template.SystemConfig
	managementConfig := template.ManagementConfig
	c.mu.Lock()
	defer c.mu.Unlock()
	device, existed := c.devices[mac]
	previous := device
	if !existed {
		keyBytes := make([]byte, 16)
		if _, err := rand.Read(keyBytes); err != nil {
			return fault("generate inform key", err)
		}
		device = Device{MAC: mac, Key: inform.DefaultKey, LastSetParam: nil, SSHUsername: "", SSHPassword: "", SSHPasswordHash: "", NextKey: hex.EncodeToString(keyBytes), Family: "", Descriptor: nil, DesiredAP: nil, DesiredSwitch: nil, DesiredVersion: "", Baseline: nil}
	}
	if setupSSH {
		passwordBytes := make([]byte, 16)
		if _, err := rand.Read(passwordBytes); err != nil {
			return fault("generate SSH password", err)
		}
		password := hex.EncodeToString(passwordBytes)
		passwordHash, err := sha512_crypt.New().Generate([]byte(password), nil)
		if err != nil {
			return fault("hash SSH password", err)
		}
		device.SSHUsername = "unifi-go"
		device.SSHPassword = password // gitleaks:allow -- generated credential, not a literal secret
		device.SSHPasswordHash = passwordHash
		for key, value := range map[string]string{
			"sshd.status": "enabled", "sshd.1.status": "enabled", "sshd.auth.passwd": "enabled",
			"users.status": "enabled", "users.1.status": "enabled", "users.1.name": device.SSHUsername,
			"users.1.password": device.SSHPasswordHash,
		} {
			systemConfig = setConfigValue(systemConfig, key, value)
		}
	}
	targetKey := device.Key
	if device.NextKey != "" {
		targetKey = device.NextKey
	}
	managementConfig = setConfigValue(managementConfig, "authkey", targetKey)
	managementConfig = setConfigValue(managementConfig, "inform_url", c.advertise)
	managementConfig = setConfigValue(managementConfig, "cfgversion", "unifi-go-1")
	template.SystemConfig = systemConfig
	template.ManagementConfig = managementConfig
	template.ConfigVersion = "unifi-go-1"
	template.ServerTime = 0
	device.LastSetParam = &template
	device.Baseline = baselineFromRawReply(template)
	device.DesiredAP, device.DesiredSwitch, device.DesiredVersion = nil, nil, ""
	c.devices[mac] = device
	if err := c.saveLocked(); err != nil {
		if existed {
			c.devices[mac] = previous
		} else {
			delete(c.devices, mac)
		}
		return err
	}
	c.queues[mac] = []Reply{template}
	return nil
}

func setConfigValue(config, key, value string) string {
	prefix := key + "="
	lines := strings.Split(strings.TrimSuffix(config, "\n"), "\n")
	for index, line := range lines {
		if strings.HasPrefix(line, prefix) {
			lines[index] = prefix + value
			return strings.Join(lines, "\n") + "\n"
		}
	}
	return strings.Join(lines, "\n") + "\n" + prefix + value + "\n"
}

// Queue enqueues a controller reply. Pending replies intentionally do not survive restart.
func (c *Controller) Queue(mac string, command Reply) error {
	mac, err := normalizeMAC(mac)
	if err != nil {
		return err
	}
	if err := command.validate(); err != nil {
		return err
	}
	parameters := make(map[string]json.RawMessage, len(command.Parameters))
	for name, value := range command.Parameters {
		parameters[name] = bytes.Clone(value)
	}
	command.Parameters = parameters
	c.mu.Lock()
	defer c.mu.Unlock()
	device, exists := c.devices[mac]
	if !exists {
		return errors.New("device is not registered")
	}
	if command.Type == ReplySetparam {
		previous := device
		device.LastSetParam = &command
		device.Baseline = baselineFromRawReply(command)
		device.DesiredAP, device.DesiredSwitch, device.DesiredVersion = nil, nil, ""
		c.devices[mac] = device
		if err := c.saveLocked(); err != nil {
			c.devices[mac] = previous
			return &network.ControlError{Code: network.PersistenceFailed, Field: ""}
		}
	}
	c.queues[mac] = append(c.queues[mac], command)
	return nil
}

// Status reports the last observed inform and current queue length for each device.
func (c *Controller) Status() []Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]Status, 0, len(c.devices))
	for mac := range c.devices {
		status := c.status[mac]
		status.MAC, status.Pending = mac, len(c.queues[mac])
		device := c.devices[mac]
		status.DesiredConfigVersion = device.DesiredVersion
		if device.LastSetParam != nil {
			status.LastSetParamVersion = network.ConfigVersion(device.LastSetParam.ConfigVersion)
		}
		result = append(result, status)
	}
	return result
}

// ServeHTTP implements the AP-facing inform endpoint.
func (c *Controller) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/inform" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxInformPayload))
	if err != nil || len(body) < 40 {
		http.Error(w, "invalid inform packet", http.StatusBadRequest)
		return
	}
	mac := net.HardwareAddr(body[8:14]).String()
	c.mu.Lock()
	defer c.mu.Unlock()
	device, exists := c.devices[mac]
	if !exists {
		http.NotFound(w, r)
		return
	}
	packet, responseKey, adoptionCompleted, err := decodeDeviceInform(body, device)
	if err != nil {
		http.Error(w, "cannot decode inform", http.StatusBadRequest)
		return
	}
	var report InformReport
	if err := json.Unmarshal(packet.Payload, &report); err != nil {
		http.Error(w, "invalid inform JSON", http.StatusBadRequest)
		return
	}
	c.status[mac] = Status{MAC: mac, LastInform: clock.Now().UTC(), ReportedConfigVersion: network.ConfigVersion(report.ConfigVersion), DesiredConfigVersion: device.DesiredVersion, LastSetParamVersion: "", Model: report.Model, Firmware: report.Firmware, IP: report.IP, IPv6: append([]string(nil), report.IPv6...), DeviceState: report.State, InformURL: report.InformURL, LastError: safeDeviceError(report.LastError), Pending: 0}
	device, err = c.recordReport(device, packet.Payload, body)
	if err != nil {
		http.Error(w, "invalid device report", http.StatusBadRequest)
		return
	}
	if version := c.awaiting[mac]; version != "" && string(version) == report.ConfigVersion {
		delete(c.awaiting, mac)
	}
	reply := Reply{Type: ReplyNoop, Command: "", Key: "", URI: "", Interval: 10, ConfigVersion: "", ManagementConfig: "", SystemConfig: "", BlockedStations: "", ServerTime: 0, Parameters: nil}
	consumeCommand := false
	if device.NextKey != "" && !adoptionCompleted {
		reply = Reply{Type: ReplyCommand, Command: CommandSetAdopt, Key: device.NextKey, URI: c.advertise, Interval: 0, ConfigVersion: "", ManagementConfig: "", SystemConfig: "", BlockedStations: "", ServerTime: 0, Parameters: nil}
	} else if queue := c.queues[mac]; len(queue) != 0 {
		reply = queue[0]
		consumeCommand = true
	}
	if adoptionCompleted {
		device.Key = device.NextKey
		device.NextKey = ""
		c.devices[mac] = device
		if err := c.saveLocked(); err != nil {
			http.Error(w, "cannot save adoption", http.StatusInternalServerError)
			return
		}
	}
	reply.ServerTime = clock.Now().UnixMilli()
	payload, err := json.Marshal(reply)
	if err != nil {
		http.Error(w, "cannot encode reply", http.StatusInternalServerError)
		return
	}
	useGCM := binary.BigEndian.Uint16(body[14:16])&8 != 0
	encoded, err := encodeControllerReply(packet.MAC, payload, responseKey, useGCM)
	if err != nil {
		http.Error(w, "cannot encode reply", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-binary")
	if _, err := w.Write(encoded); err == nil && consumeCommand {
		c.queues[mac] = c.queues[mac][1:]
	}
}

func decodeDeviceInform(body []byte, device Device) (*inform.Packet, string, bool, error) {
	responseKey := device.Key
	packet, err := decodeInform(body, responseKey)
	if err == nil {
		return packet, responseKey, false, nil
	}
	if device.NextKey == "" {
		return nil, responseKey, false, fault("decode inform", err)
	}
	responseKey = device.NextKey
	packet, err = decodeInform(body, responseKey)
	if err != nil {
		return nil, responseKey, false, fault("decode inform with assigned key", err)
	}
	return packet, responseKey, true, nil
}

func fault(operation string, err error) error {
	slog.Error("controller operation failed", "operation", operation, "error", err)
	return fmt.Errorf("%s: %w", operation, err)
}
