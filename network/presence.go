package network

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type policyValue interface {
	~bool | ~string | ~uint16 | ~int |
		[]RadioBand | []VLANID | []WiFiNetwork | []RadioConfig | []SwitchPortConfig |
		WiFiSecurity | PowerConfig | SSHConfig
}

// Optional distinguishes omitted, supplied, and explicitly cleared policy.
type Optional[T policyValue] struct {
	Present bool
	Null    bool
	Value   T
}

// Supplied returns an explicitly supplied policy value.
func Supplied[T policyValue](value T) Optional[T] {
	return Optional[T]{Present: true, Value: value}
}

// Cleared returns an explicitly cleared policy value.
func Cleared[T policyValue]() Optional[T] {
	return Optional[T]{Present: true, Null: true}
}

// IsZero reports whether policy was omitted.
func (value Optional[T]) IsZero() bool {
	return !value.Present
}

// MarshalJSON encodes supplied policy as its plain JSON value.
func (value Optional[T]) MarshalJSON() ([]byte, error) {
	if !value.Present || value.Null {
		return []byte("null"), nil
	}
	encoded, err := json.Marshal(value.Value)
	if err != nil {
		return nil, fmt.Errorf("marshal optional value: %w", err)
	}
	return encoded, nil
}

// UnmarshalJSON records whether policy was supplied or explicitly cleared.
func (value *Optional[T]) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if bytes.Equal(trimmed, []byte("null")) {
		var zero T
		*value = Cleared[T]()
		value.Value = zero
		return nil
	}
	var decoded T
	if err := json.Unmarshal(data, &decoded); err != nil {
		return fmt.Errorf("unmarshal optional value: %w", err)
	}
	*value = Supplied(decoded)
	return nil
}
