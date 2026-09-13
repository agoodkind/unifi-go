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

type controlRequest struct {
	Operation string        `json:"operation"`
	Device    DeviceID      `json:"device,omitempty"`
	AP        *APConfig     `json:"ap,omitempty"`
	Switch    *SwitchConfig `json:"switch,omitempty"`
	Config    *Config       `json:"config,omitempty"`
}

type controlResponse struct {
	Error   *ControlError    `json:"error,omitempty"`
	Version ConfigVersion    `json:"version,omitempty"`
	Device  *DeviceSnapshot  `json:"device,omitempty"`
	Devices []DeviceSnapshot `json:"devices,omitempty"`
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
