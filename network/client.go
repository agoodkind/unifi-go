package network

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

// Client calls the controller over a local Unix socket.
type Client struct{ http *http.Client }

// Command carries an operator-selected device command and its JSON fields.
type Command struct {
	Name       string                     `json:"name"`
	Parameters map[string]json.RawMessage `json:"parameters"`
}

// BaselineImport establishes configuration bytes and explicit typed identities without delivery.
type BaselineImport struct {
	Config Config        `json:"config"`
	AP     *APConfig     `json:"ap,omitempty"`
	Switch *SwitchConfig `json:"switch,omitempty"`
}

type controlRequest struct {
	Operation    string            `json:"operation"`
	Device       DeviceID          `json:"device,omitempty"`
	AP           *APConfig         `json:"ap,omitempty"`
	Switch       *SwitchConfig     `json:"switch,omitempty"`
	Config       *Config           `json:"config,omitempty"`
	TypedCommand *Command          `json:"typed_command,omitempty"`
	Baseline     *BaselineImport   `json:"baseline,omitempty"`
	PreviewToken PreviewToken      `json:"preview_token,omitempty"`
	WiFiAdd      *AddWiFiRequest   `json:"wifi_add,omitempty"`
	WiFiSet      *SetWiFiRequest   `json:"wifi_set,omitempty"`
	WiFiRemove   *string           `json:"wifi_remove,omitempty"`
	Radio        *RadioConfig      `json:"radio,omitempty"`
	Port         *SwitchPortConfig `json:"port,omitempty"`
}

type controlResponse struct {
	Error        *ControlError     `json:"error,omitempty"`
	Version      ConfigVersion     `json:"version,omitempty"`
	Device       *DeviceSnapshot   `json:"device,omitempty"`
	Devices      []DeviceSnapshot  `json:"devices,omitempty"`
	Preview      *ConfigPreview    `json:"preview,omitempty"`
	WiFiNetworks []WiFiNetworkView `json:"wifi_networks,omitempty"`
}

// Dial creates a client for socket; connections open on demand.
func Dial(socket string) *Client {
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	return &Client{http: &http.Client{Transport: transport, Timeout: 45 * time.Second}}
}

// ApplyAP queues access point configuration and returns its desired version.
func (client *Client) ApplyAP(ctx context.Context, id DeviceID, config APConfig) (ConfigVersion, error) {
	response, err := client.call(ctx, controlRequest{Operation: "apply-ap", Device: id, AP: &config})
	return response.Version, err
}

// ApplySwitch queues switch configuration and returns its desired version.
func (client *Client) ApplySwitch(ctx context.Context, id DeviceID, config SwitchConfig) (ConfigVersion, error) {
	response, err := client.call(ctx, controlRequest{Operation: "apply-switch", Device: id, Switch: &config})
	return response.Version, err
}

// ApplyConfig queues complete configuration records and returns their supplied version.
func (client *Client) ApplyConfig(ctx context.Context, id DeviceID, config Config) (ConfigVersion, error) {
	if err := config.Validate(); err != nil {
		return "", err
	}
	response, err := client.call(ctx, controlRequest{Operation: "apply-config", Device: id, Config: &config})
	return response.Version, err
}

// SendCommand queues an arbitrary device command without replacing configuration.
func (client *Client) SendCommand(ctx context.Context, id DeviceID, command Command) error {
	_, err := client.call(ctx, controlRequest{Operation: "command", Device: id, TypedCommand: &command})
	return err
}

// ImportBaseline records a baseline without queueing or claiming device application.
func (client *Client) ImportBaseline(ctx context.Context, id DeviceID, baseline BaselineImport) error {
	if err := baseline.Config.Validate(); err != nil {
		return err
	}
	_, err := client.call(ctx, controlRequest{Operation: "baseline-import", Device: id, Baseline: &baseline})
	return err
}

// Device returns the latest observed device state.
func (client *Client) Device(ctx context.Context, id DeviceID) (DeviceSnapshot, error) {
	response, err := client.call(ctx, controlRequest{Operation: "device", Device: id})
	if err != nil {
		return DeviceSnapshot{}, err
	}
	if response.Device == nil {
		return DeviceSnapshot{}, errors.New("controller omitted device")
	}
	return *response.Device, nil
}

// Devices returns registered devices sorted by identifier.
func (client *Client) Devices(ctx context.Context) ([]DeviceSnapshot, error) {
	response, err := client.call(ctx, controlRequest{Operation: "devices"})
	return response.Devices, err
}

// WiFiNetworks returns non-secret desired WiFi resources.
func (client *Client) WiFiNetworks(ctx context.Context, id DeviceID) ([]WiFiNetworkView, error) {
	response, err := client.call(ctx, controlRequest{Operation: "wifi-list", Device: id})
	if response.WiFiNetworks == nil && err == nil {
		response.WiFiNetworks = []WiFiNetworkView{}
	}
	return response.WiFiNetworks, err
}

// AddWiFi copies an existing WiFi resource under a new name and secret.
func (client *Client) AddWiFi(ctx context.Context, id DeviceID, request AddWiFiRequest) (ConfigVersion, error) {
	response, err := client.call(ctx, controlRequest{Operation: "wifi-add", Device: id, WiFiAdd: &request})
	return response.Version, err
}

// SetWiFi changes one named WiFi resource.
func (client *Client) SetWiFi(ctx context.Context, id DeviceID, request SetWiFiRequest) (ConfigVersion, error) {
	response, err := client.call(ctx, controlRequest{Operation: "wifi-set", Device: id, WiFiSet: &request})
	return response.Version, err
}

// RemoveWiFi removes one named WiFi resource.
func (client *Client) RemoveWiFi(ctx context.Context, id DeviceID, name string) (ConfigVersion, error) {
	response, err := client.call(ctx, controlRequest{Operation: "wifi-remove", Device: id, WiFiRemove: &name})
	return response.Version, err
}

// SetRadio changes one physical access point radio.
func (client *Client) SetRadio(ctx context.Context, id DeviceID, config RadioConfig) (ConfigVersion, error) {
	response, err := client.call(ctx, controlRequest{Operation: "radio-set", Device: id, Radio: &config})
	return response.Version, err
}

// SetSwitchPort changes one physical switch port.
func (client *Client) SetSwitchPort(ctx context.Context, id DeviceID, config SwitchPortConfig) (ConfigVersion, error) {
	response, err := client.call(ctx, controlRequest{Operation: "port-set", Device: id, Port: &config})
	return response.Version, err
}

func (client *Client) call(ctx context.Context, request controlRequest) (controlResponse, error) {
	var result controlResponse
	data, err := json.Marshal(request)
	if err != nil {
		return result, errors.New("cannot encode control request")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://local/control", bytes.NewReader(data))
	if err != nil {
		return result, errors.New("cannot create control request")
	}
	response, err := client.http.Do(req)
	if err != nil {
		return result, errors.New("cannot reach controller")
	}
	defer response.Body.Close()
	if err := json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(&result); err != nil {
		return result, errors.New("invalid controller response")
	}
	if response.StatusCode != http.StatusOK {
		if result.Error != nil {
			return result, result.Error
		}
		return result, &ControlError{Code: RequestFailed, Field: ""}
	}
	return result, nil
}
