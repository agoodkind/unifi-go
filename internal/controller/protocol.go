package controller

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"unicode/utf8"
)

// ReplyType identifies a controller response carried by an inform exchange.
type ReplyType string

const (
	// ReplyNoop asks the device to continue its normal inform interval.
	ReplyNoop ReplyType = "noop"
	// ReplySetparam applies management and system configuration.
	ReplySetparam ReplyType = "setparam"
	// ReplyCommand carries an imperative controller command.
	ReplyCommand ReplyType = "cmd"
)

// CommandType identifies a command reply.
type CommandType string

const (
	// CommandSetAdopt assigns an inform key and controller URL.
	CommandSetAdopt CommandType = "set-adopt"
)

// Reply is the supported controller-to-device inform response.
type Reply struct {
	Type             ReplyType                  `json:"_type"`
	Command          CommandType                `json:"cmd,omitempty"`
	Key              string                     `json:"key,omitempty"`
	URI              string                     `json:"uri,omitempty"`
	Interval         int                        `json:"interval,omitempty"`
	ConfigVersion    string                     `json:"cfgversion,omitempty"`
	ManagementConfig string                     `json:"mgmt_cfg,omitempty"`
	SystemConfig     string                     `json:"system_cfg,omitempty"`
	BlockedStations  string                     `json:"blocked_sta,omitempty"`
	ServerTime       int64                      `json:"server_time_in_utc,omitempty"`
	Parameters       map[string]json.RawMessage `json:"-"`
}

// MarshalJSON flattens operator parameters into the device command object.
func (reply Reply) MarshalJSON() ([]byte, error) {
	type plainReply Reply
	data, err := json.Marshal(plainReply(reply))
	if err != nil {
		return nil, errors.New("cannot encode reply")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, errors.New("cannot encode reply fields")
	}
	for name, value := range reply.Parameters {
		if reservedParameter(name) || !utf8.ValidString(name) || !json.Valid(value) || !utf8.Valid(value) {
			return nil, errors.New("invalid command parameter")
		}
		fields[name] = value
	}
	encoded, err := json.Marshal(fields)
	if err != nil {
		return nil, errors.New("cannot encode command fields")
	}
	return encoded, nil
}

// UnmarshalJSON retains arbitrary command fields while decoding transport framing.
func (reply *Reply) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return errors.New("invalid reply")
	}
	var kind ReplyType
	if err := json.Unmarshal(fields["_type"], &kind); err != nil {
		return errors.New("invalid reply type")
	}
	parameters := make(map[string]json.RawMessage)
	if kind == ReplyCommand {
		for name, value := range fields {
			if !reservedParameter(name) {
				parameters[name] = value
				delete(fields, name)
			}
		}
	}
	framing, err := json.Marshal(fields)
	if err != nil {
		return errors.New("invalid reply framing")
	}
	type plainReply Reply
	var decoded plainReply
	decoder := json.NewDecoder(bytes.NewReader(framing))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return errors.New("invalid reply fields")
	}
	*reply = Reply(decoded)
	if kind == ReplyCommand {
		reply.Parameters = parameters
	}
	// Adoption callers also consume these fields directly.
	if reply.Command == CommandSetAdopt {
		if err := json.Unmarshal(parameters["key"], &reply.Key); err != nil {
			return errors.New("invalid adoption key")
		}
		if err := json.Unmarshal(parameters["uri"], &reply.URI); err != nil {
			return errors.New("invalid adoption URI")
		}
	}
	return nil
}

func reservedParameter(name string) bool {
	return name == "_type" || name == "cmd" || name == "server_time_in_utc"
}

func (reply Reply) validate() error {
	if len(reply.Parameters) != 0 && reply.Type != ReplyCommand {
		return errors.New("parameters require a command reply")
	}
	for name, value := range reply.Parameters {
		if reservedParameter(name) || !utf8.ValidString(name) || !json.Valid(value) || !utf8.Valid(value) {
			return errors.New("invalid command parameter")
		}
	}
	switch reply.Type {
	case ReplyNoop:
		return nil
	case ReplySetparam:
		if reply.ManagementConfig == "" && reply.SystemConfig == "" {
			return errors.New("setparam requires mgmt_cfg or system_cfg")
		}
		return nil
	case ReplyCommand:
		if reply.Command == "" || !utf8.ValidString(string(reply.Command)) {
			return errors.New("command requires a valid name")
		}
		if reply.Command == CommandSetAdopt {
			return reply.validateAdoption()
		}
		return nil
	default:
		return errors.New("unsupported reply type")
	}
}

func (reply Reply) validateAdoption() error {
	key, uri := reply.Key, reply.URI
	if value, exists := reply.Parameters["key"]; exists {
		key = ""
		if err := json.Unmarshal(value, &key); err != nil {
			return errors.New("set-adopt requires a string key")
		}
	}
	if value, exists := reply.Parameters["uri"]; exists {
		uri = ""
		if err := json.Unmarshal(value, &uri); err != nil {
			return errors.New("set-adopt requires a string URI")
		}
	}
	decoded, err := hex.DecodeString(key)
	if err != nil || len(decoded) != 16 {
		return errors.New("set-adopt requires a 16-byte hexadecimal key")
	}
	address, err := url.Parse(uri)
	if err != nil || address.Hostname() == "" || (address.Scheme != "http" && address.Scheme != "https") {
		return errors.New("set-adopt requires an HTTP or HTTPS URI")
	}
	return nil
}
