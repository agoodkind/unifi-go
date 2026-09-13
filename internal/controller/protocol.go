package controller

import "errors"

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
	Type             ReplyType   `json:"_type"`
	Command          CommandType `json:"cmd,omitempty"`
	Key              string      `json:"key,omitempty"`
	URI              string      `json:"uri,omitempty"`
	Interval         int         `json:"interval,omitempty"`
	ConfigVersion    string      `json:"cfgversion,omitempty"`
	ManagementConfig string      `json:"mgmt_cfg,omitempty"`
	SystemConfig     string      `json:"system_cfg,omitempty"`
	BlockedStations  string      `json:"blocked_sta,omitempty"`
	ServerTime       int64       `json:"server_time_in_utc,omitempty"`
}

func (reply Reply) validate() error {
	switch reply.Type {
	case ReplyNoop:
		return nil
	case ReplySetparam:
		if reply.ManagementConfig == "" && reply.SystemConfig == "" {
			return errors.New("setparam requires mgmt_cfg or system_cfg")
		}
		return nil
	case ReplyCommand:
		if reply.Command != CommandSetAdopt {
			return errors.New("unsupported command")
		}
		if reply.Key == "" || reply.URI == "" {
			return errors.New("set-adopt requires key and uri")
		}
		return nil
	default:
		return errors.New("unsupported reply type")
	}
}
