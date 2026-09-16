package syncplan

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
)

// secretMarkers name the substrings a credential-bearing member carries. The
// controller spells shared secrets several ways across collections, so the rule
// matches the member name rather than a fixed list of fields.
var secretMarkers = []string{
	"password",
	"passphrase",
	"psk",
	"secret",
	"token",
	"preshared",
	"credential",
	"_key",
}

// secretMember reports whether a member of this name holds credential material.
// The bare name "key" identifies a site setting rather than a secret, so it
// stays readable.
func secretMember(name string) bool {
	lowered := strings.ToLower(name)
	if lowered == "key" {
		return false
	}
	for _, marker := range secretMarkers {
		if strings.Contains(lowered, marker) {
			return true
		}
	}
	return strings.HasSuffix(lowered, "key")
}

// carriesText reports whether a value can hold credential material.
func carriesText(trimmed string) bool {
	return strings.HasPrefix(trimmed, `"`) || strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}

// digest returns a short stable fingerprint, so a changed secret stays visible
// in a diff while its value never reaches the output.
func digest(raw json.RawMessage) string {
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("sha256:%x", sum[:4])
}

// redact replaces every credential-bearing member of one value with a digest.
// The comparison reads the real values, so redaction changes only what an
// operator reads.
func redact(name string, raw json.RawMessage) (json.RawMessage, error) {
	if raw == nil {
		return nil, nil
	}
	trimmed := strings.TrimSpace(string(raw))
	// A credential is carried as text or as a structure of text. A boolean or a
	// number beside a credential name states whether the feature is on, so it
	// stays readable.
	if secretMember(name) && carriesText(trimmed) {
		encoded, err := json.Marshal(digest(raw))
		if err != nil {
			return nil, failure("encode redacted value", err)
		}
		return encoded, nil
	}
	if strings.HasPrefix(trimmed, "{") {
		return redactObject(raw)
	}
	if strings.HasPrefix(trimmed, "[") {
		return redactArray(raw)
	}
	return raw, nil
}

func redactObject(raw json.RawMessage) (json.RawMessage, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, failure("read object members", err)
	}
	result := make(map[string]json.RawMessage, len(members))
	for name, value := range members {
		replaced, err := redact(name, value)
		if err != nil {
			return nil, err
		}
		result[name] = replaced
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, failure("encode redacted object", err)
	}
	return encoded, nil
}

func redactArray(raw json.RawMessage) (json.RawMessage, error) {
	var elements []json.RawMessage
	if err := json.Unmarshal(raw, &elements); err != nil {
		return nil, failure("read array elements", err)
	}
	result := make([]json.RawMessage, 0, len(elements))
	for _, element := range elements {
		replaced, err := redact("", element)
		if err != nil {
			return nil, err
		}
		result = append(result, replaced)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, failure("encode redacted array", err)
	}
	return encoded, nil
}
