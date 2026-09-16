package syncstore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"
)

const indentStep = "  "

// MarshalCanonical returns the stable text form of one JSON value, with object
// members in sorted order and a fixed indent, so two reads of the same record
// produce the same bytes and a review diff shows only real changes.
func MarshalCanonical(raw json.RawMessage) ([]byte, error) {
	out := new(bytes.Buffer)
	if err := writeValue(raw, 0, out); err != nil {
		return nil, err
	}
	out.WriteString("\n")
	return out.Bytes(), nil
}

func writeValue(raw json.RawMessage, depth int, out *bytes.Buffer) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return fmt.Errorf("canonical json: empty value")
	}
	switch trimmed[0] {
	case '{':
		return writeObject(trimmed, depth, out)
	case '[':
		return writeArray(trimmed, depth, out)
	default:
		compact := new(bytes.Buffer)
		if err := json.Compact(compact, trimmed); err != nil {
			return encodeFailure("canonical json scalar", err)
		}
		out.Write(compact.Bytes())
		return nil
	}
}

func writeObject(raw json.RawMessage, depth int, out *bytes.Buffer) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return encodeFailure("canonical json object", err)
	}
	if len(members) == 0 {
		out.WriteString("{}")
		return nil
	}
	names := make([]string, 0, len(members))
	for name := range members {
		names = append(names, name)
	}
	slices.Sort(names)
	out.WriteString("{\n")
	for index, name := range names {
		out.WriteString(strings.Repeat(indentStep, depth+1))
		encoded, err := json.Marshal(name)
		if err != nil {
			return encodeFailure("canonical json member name", err)
		}
		out.Write(encoded)
		out.WriteString(": ")
		if err := writeValue(members[name], depth+1, out); err != nil {
			return err
		}
		if index < len(names)-1 {
			out.WriteString(",")
		}
		out.WriteString("\n")
	}
	out.WriteString(strings.Repeat(indentStep, depth))
	out.WriteString("}")
	return nil
}

func writeArray(raw json.RawMessage, depth int, out *bytes.Buffer) error {
	var elements []json.RawMessage
	if err := json.Unmarshal(raw, &elements); err != nil {
		return encodeFailure("canonical json array", err)
	}
	if len(elements) == 0 {
		out.WriteString("[]")
		return nil
	}
	out.WriteString("[\n")
	for index, element := range elements {
		out.WriteString(strings.Repeat(indentStep, depth+1))
		if err := writeValue(element, depth+1, out); err != nil {
			return err
		}
		if index < len(elements)-1 {
			out.WriteString(",")
		}
		out.WriteString("\n")
	}
	out.WriteString(strings.Repeat(indentStep, depth))
	out.WriteString("]")
	return nil
}

func encodeFailure(message string, err error) error {
	slog.Error(message, slog.String("error", err.Error()))
	return fmt.Errorf("%s: %w", message, err)
}
