package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"unicode/utf8"

	"goodkind.io/unifi-go/network"
)

// Operation names the local CLI requests.
type Operation string

const (
	// OpStatus reads device status.
	OpStatus Operation = "status"
	// OpImport registers an existing inform key.
	OpImport Operation = "import"
	// OpSend queues a raw controller reply.
	OpSend Operation = "send"
	// OpAdopt starts the inform key transition and provisioning.
	OpAdopt Operation = "adopt"
	// OpMode reads whether this controller answers device informs.
	OpMode Operation = "mode"
	// OpPromote binds the device listener.
	OpPromote Operation = "promote"
	// OpDemote releases the device listener.
	OpDemote Operation = "demote"
)

// ControlRequest is sent over the private local socket; secrets use file references.
type ControlRequest struct {
	Device       network.DeviceID          `json:"device,omitempty"`
	AP           *network.APConfig         `json:"ap,omitempty"`
	Switch       *network.SwitchConfig     `json:"switch,omitempty"`
	Config       *network.Config           `json:"config,omitempty"`
	Operation    Operation                 `json:"operation"`
	MAC          string                    `json:"mac,omitempty"`
	KeyFile      string                    `json:"key_file,omitempty"`
	Command      *Reply                    `json:"command,omitempty"`
	TypedCommand *network.Command          `json:"typed_command,omitempty"`
	Baseline     *network.BaselineImport   `json:"baseline,omitempty"`
	SetupSSH     bool                      `json:"setup_ssh,omitempty"`
	PreviewToken network.PreviewToken      `json:"preview_token,omitempty"`
	WiFiAdd      *network.AddWiFiRequest   `json:"wifi_add,omitempty"`
	WiFiSet      *network.SetWiFiRequest   `json:"wifi_set,omitempty"`
	WiFiRemove   *string                   `json:"wifi_remove,omitempty"`
	Radio        *network.RadioConfig      `json:"radio,omitempty"`
	Port         *network.SwitchPortConfig `json:"port,omitempty"`
}

type controlResponse struct {
	Error        *network.ControlError     `json:"error,omitempty"`
	Version      network.ConfigVersion     `json:"version,omitempty"`
	Device       *network.DeviceSnapshot   `json:"device,omitempty"`
	Devices      []network.DeviceSnapshot  `json:"devices,omitempty"`
	Preview      *network.ConfigPreview    `json:"preview,omitempty"`
	WiFiNetworks []network.WiFiNetworkView `json:"wifi_networks,omitempty"`
}

// Control handles CLI requests on a separate Unix socket.
func (c *Controller) Control(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	request, ok := decodeControlRequest(w, r)
	if !ok {
		return
	}
	if modeOperation(request.Operation) {
		c.serveMode(r.Context(), w, request.Operation)
		return
	}
	if request.Operation == OpStatus {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(c.Status()); err != nil {
			return
		}
		return
	}
	response, err := c.dispatch(request)
	if err != nil {
		if typedControlOperation(request.Operation) {
			writeControlError(w, err)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if typedControlOperation(request.Operation) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			return
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// dispatch runs one control operation and returns what the caller reads back.
func (c *Controller) dispatch(request ControlRequest) (controlResponse, error) {
	var err error
	var response controlResponse
	switch request.Operation {
	case "apply-ap":
		response.Version, err = c.apply(request.Device, network.FamilyAP, request.AP, request.Switch, request.PreviewToken)
	case "apply-switch":
		response.Version, err = c.apply(request.Device, network.FamilySwitch, request.AP, request.Switch, request.PreviewToken)
	case "preview-ap", "preview-switch":
		response.Preview, err = c.previewControl(request)
	case "apply-config":
		response.Version, err = c.applyConfig(request.Device, request.Config)
	case "command":
		if request.TypedCommand == nil {
			err = &network.ControlError{Code: network.InvalidConfig}
		} else {
			var command Reply
			command.Type, command.Command, command.Parameters = ReplyCommand, CommandType(request.TypedCommand.Name), request.TypedCommand.Parameters
			err = c.Queue(string(request.Device), command)
		}
	case "baseline-import":
		err = c.importBaseline(request.Device, request.Baseline)
	case "wifi-list", "wifi-add", "wifi-set", "wifi-remove", "radio-set", "port-set":
		response, err = c.resourceControl(request)
	case "device":
		var snapshot network.DeviceSnapshot
		snapshot, err = c.deviceSnapshot(request.Device)
		response.Device = &snapshot
	case "devices":
		response.Devices, err = c.deviceSnapshots()
	case OpImport:
		var data []byte
		data, err = readSecret(request.KeyFile)
		if err == nil {
			err = c.Register(request.MAC, string(data))
		}
	case OpSend:
		if request.Command == nil {
			err = errors.New("send requires a typed command")
		} else {
			err = c.Queue(request.MAC, *request.Command)
		}
	case OpAdopt:
		if request.Command == nil {
			err = errors.New("adopt requires a typed setparam template")
		} else {
			err = c.Adopt(request.MAC, *request.Command, request.SetupSSH)
		}
	case OpStatus, OpMode, OpPromote, OpDemote:
		err = errors.New("operation is answered before dispatch")
	default:
		err = errors.New("unknown operation")
	}
	return response, err
}

func typedControlOperation(operation Operation) bool {
	switch operation {
	case "apply-ap", "apply-switch", "preview-ap", "preview-switch", "apply-config", "device", "devices", "command", "baseline-import", "wifi-list", "wifi-add", "wifi-set", "wifi-remove", "radio-set", "port-set":
		return true
	case OpStatus, OpImport, OpSend, OpAdopt, OpMode, OpPromote, OpDemote:
		return false
	default:
		return false
	}
}

func validResourceRequest(request ControlRequest, expected string) bool {
	if request.AP != nil || request.Switch != nil || request.Config != nil || request.MAC != "" || request.KeyFile != "" || request.Command != nil || request.TypedCommand != nil || request.Baseline != nil || request.SetupSSH || request.PreviewToken != "" {
		return false
	}
	fields := map[string]bool{
		"wifi-add":    request.WiFiAdd != nil,
		"wifi-set":    request.WiFiSet != nil,
		"wifi-remove": request.WiFiRemove != nil,
		"radio-set":   request.Radio != nil,
		"port-set":    request.Port != nil,
	}
	for name, present := range fields {
		if present != (name == expected) {
			return false
		}
	}
	return true
}

func (c *Controller) resourceControl(request ControlRequest) (controlResponse, error) {
	var response controlResponse
	expected := string(request.Operation)
	if request.Operation == "wifi-list" {
		expected = ""
	}
	if !validResourceRequest(request, expected) {
		return response, &network.ControlError{Code: network.InvalidConfig}
	}
	var err error
	switch request.Operation {
	case "wifi-list":
		response.WiFiNetworks, err = c.wifiNetworks(request.Device)
	case "wifi-add":
		response.Version, err = c.addWiFi(request.Device, *request.WiFiAdd)
	case "wifi-set":
		response.Version, err = c.setWiFi(request.Device, *request.WiFiSet)
	case "wifi-remove":
		response.Version, err = c.removeWiFi(request.Device, *request.WiFiRemove)
	case "radio-set":
		response.Version, err = c.setRadio(request.Device, *request.Radio)
	case "port-set":
		response.Version, err = c.setSwitchPort(request.Device, *request.Port)
	case OpStatus, OpImport, OpSend, OpAdopt, OpMode, OpPromote, OpDemote:
		err = &network.ControlError{Code: network.InvalidConfig}
	default:
		err = &network.ControlError{Code: network.InvalidConfig}
	}
	return response, err
}

func decodeControlRequest(w http.ResponseWriter, r *http.Request) (ControlRequest, bool) {
	var request ControlRequest
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8388608))
	if err != nil {
		http.Error(w, "invalid control request", http.StatusBadRequest)
		return request, false
	}
	if !ValidConfigEnvelopeEncoding(body) {
		writeControlError(w, &network.ControlError{Code: network.InvalidEncoding, Field: ""})
		return request, false
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "invalid control request", http.StatusBadRequest)
		return request, false
	}
	if decoder.Decode(new(json.RawMessage)) != io.EOF {
		http.Error(w, "invalid control request", http.StatusBadRequest)
		return request, false
	}
	return request, true
}

// ValidConfigEnvelopeEncoding rejects lossy Unicode in configuration envelope fields.
func ValidConfigEnvelopeEncoding(body []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	opening, err := decoder.Token()
	if err != nil {
		return true
	}
	delimiter, ok := opening.(json.Delim)
	if !ok || delimiter != '{' {
		return true
	}
	for decoder.More() {
		name, ok := controlObjectMember(decoder)
		if !ok {
			return true
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return true
		}
		if strings.EqualFold(name, "config") && !validConfigObjectEncoding(value) {
			return false
		}
		if strings.EqualFold(name, "baseline") && !ValidConfigEnvelopeEncoding(value) {
			return false
		}
	}
	return true
}

func validConfigObjectEncoding(value []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(value))
	opening, err := decoder.Token()
	if err != nil {
		return true
	}
	delimiter, ok := opening.(json.Delim)
	if !ok || delimiter != '{' {
		return true
	}
	for decoder.More() {
		name, ok := controlObjectMember(decoder)
		if !ok {
			return true
		}
		var field json.RawMessage
		if err := decoder.Decode(&field); err != nil {
			return true
		}
		if configTextField(name) && !validJSONStringEncoding(field) {
			return false
		}
	}
	return true
}

func controlObjectMember(decoder *json.Decoder) (string, bool) {
	token, err := decoder.Token()
	if err != nil {
		return "", false
	}
	name, ok := token.(string)
	return name, ok
}

func configTextField(name string) bool {
	return strings.EqualFold(name, "version") || strings.EqualFold(name, "management") || strings.EqualFold(name, "system")
}

func validJSONStringEncoding(value []byte) bool {
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return true
	}
	for index := 1; index < len(value)-1; {
		if value[index] == '\\' {
			next, ok := jsonEscapeEnd(value, index)
			if !ok {
				return false
			}
			index = next
			continue
		}
		if value[index] < utf8.RuneSelf {
			index++
			continue
		}
		_, size := utf8.DecodeRune(value[index:])
		if size == 1 {
			return false
		}
		index += size
	}
	return true
}

func jsonEscapeEnd(value []byte, index int) (int, bool) {
	if index+1 >= len(value)-1 || value[index+1] != 'u' {
		return index + 2, true
	}
	if index+6 > len(value)-1 {
		return 0, false
	}
	code, ok := jsonCodePoint(value[index+2 : index+6])
	if !ok {
		return 0, false
	}
	if code >= 0xdc00 && code <= 0xdfff {
		return 0, false
	}
	if code < 0xd800 || code > 0xdbff {
		return index + 6, true
	}
	if index+12 > len(value)-1 || value[index+6] != '\\' || value[index+7] != 'u' {
		return 0, false
	}
	low, ok := jsonCodePoint(value[index+8 : index+12])
	if !ok || low < 0xdc00 || low > 0xdfff {
		return 0, false
	}
	return index + 12, true
}

func jsonCodePoint(value []byte) (rune, bool) {
	if len(value) != 4 {
		return 0, false
	}
	var code rune
	for _, character := range value {
		code <<= 4
		switch {
		case character >= '0' && character <= '9':
			code += rune(character - '0')
		case character >= 'a' && character <= 'f':
			code += rune(character-'a') + 10
		case character >= 'A' && character <= 'F':
			code += rune(character-'A') + 10
		default:
			return 0, false
		}
	}
	return code, true
}

func (c *Controller) applyConfig(id network.DeviceID, config *network.Config) (network.ConfigVersion, error) {
	if config == nil {
		return "", &network.ControlError{Code: network.InvalidConfig, Field: ""}
	}
	if err := config.Validate(); err != nil {
		slog.Error("configuration encoding validation failed", "error", err)
		return "", fmt.Errorf("validate configuration encoding: %w", err)
	}
	if config.Version == "" || config.Management == "" && config.System == "" {
		return "", &network.ControlError{Code: network.InvalidConfig, Field: ""}
	}
	command := Reply{Type: ReplySetparam, ConfigVersion: string(config.Version), ManagementConfig: config.Management, SystemConfig: config.System, Command: "", Key: "", URI: "", Interval: 0, BlockedStations: "", ServerTime: 0, Parameters: nil}
	if err := c.Queue(string(id), command); err != nil {
		return "", err
	}
	return config.Version, nil
}

func writeControlError(w http.ResponseWriter, err error) {
	failure := &network.ControlError{Code: network.RequestFailed, Field: ""}
	if typed, ok := errors.AsType[*network.ControlError](err); ok {
		failure = typed
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	if err := json.NewEncoder(w).Encode(controlResponse{Error: failure, Version: "", Device: nil, Devices: nil, Preview: nil, WiFiNetworks: nil}); err != nil {
		return
	}
}

func readSecret(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("a credential file is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("cannot read credential file")
	}
	return data, nil
}

// modeOperation reports whether this operation reads or changes the listener.
func modeOperation(operation Operation) bool {
	return operation == OpMode || operation == OpPromote || operation == OpDemote
}

// serveMode answers the three listener operations with the resulting mode.
func (c *Controller) serveMode(ctx context.Context, w http.ResponseWriter, operation Operation) {
	var report ModeReport
	var err error
	switch operation {
	case OpPromote:
		report, err = c.Promote(ctx)
	case OpDemote:
		report, err = c.Demote(ctx)
	case OpMode:
		report = c.Mode()
	case OpStatus, OpImport, OpSend, OpAdopt:
		err = errors.New("operation is not a listener operation")
	default:
		err = errors.New("operation is not a listener operation")
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(report); err != nil {
		return
	}
}
