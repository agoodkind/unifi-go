// Package configmap encodes and decodes deterministic key-value maps.
package configmap

import (
	"fmt"
	"maps"
	"sort"
	"strings"
)

// Values stores configuration values by key.
type Values map[string]string

// Parse decodes newline-separated key-value records.
func Parse(encoded string) (Values, error) {
	values := Values{}
	if encoded == "" {
		return values, nil
	}

	encoded, _ = strings.CutSuffix(encoded, "\n")
	if encoded == "" {
		return nil, fmt.Errorf("parse config map: empty record")
	}

	for record := range strings.SplitSeq(encoded, "\n") {
		key, value, found := strings.Cut(record, "=")
		if !found {
			return nil, fmt.Errorf("parse config map record %q: missing separator", record)
		}
		if err := validateRecord(key, value); err != nil {
			return nil, err
		}
		if _, exists := values[key]; exists {
			return nil, fmt.Errorf("parse config map: duplicate key %q", key)
		}
		values[key] = value
	}

	return values, nil
}

// Clone returns an independent copy of values.
func (values Values) Clone() Values {
	clone := make(Values, len(values))
	maps.Copy(clone, values)
	return clone
}

// Encode returns sorted key-value records with a trailing newline.
func (values Values) Encode() (string, error) {
	keys := make([]string, 0, len(values))
	for key, value := range values {
		if err := validateRecord(key, value); err != nil {
			return "", err
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var encoded strings.Builder
	for _, key := range keys {
		encoded.WriteString(key)
		encoded.WriteByte('=')
		encoded.WriteString(values[key])
		encoded.WriteByte('\n')
	}
	return encoded.String(), nil
}

// Set validates and stores a key-value record.
func (values Values) Set(key string, value string) error {
	if err := validateRecord(key, value); err != nil {
		return err
	}
	if values == nil {
		return fmt.Errorf("set config map key %q: nil map", key)
	}
	values[key] = value
	return nil
}

// Delete removes key from values.
func (values Values) Delete(key string) {
	delete(values, key)
}

func validateRecord(key string, value string) error {
	if key == "" {
		return fmt.Errorf("empty key")
	}
	if strings.ContainsRune(key, '=') {
		return fmt.Errorf("key contains separator")
	}
	if strings.ContainsAny(key, "\r\n") {
		return fmt.Errorf("key contains newline")
	}
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("value contains newline")
	}
	return nil
}
