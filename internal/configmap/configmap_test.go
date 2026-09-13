package configmap_test

import (
	"reflect"
	"testing"

	"goodkind.io/unifi-go/internal/configmap"
)

func TestParseRoundTripPreservesValues(t *testing.T) {
	encoded := "empty=\nequals=first=second\nspaced=  keep spaces  \n"

	values, err := configmap.Parse(encoded)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	want := configmap.Values{
		"empty":  "",
		"equals": "first=second",
		"spaced": "  keep spaces  ",
	}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("Parse() = %#v, want %#v", values, want)
	}

	got, err := values.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if got != encoded {
		t.Fatalf("Encode() = %q, want %q", got, encoded)
	}
}

func TestEncodeSortsKeysAndAddsTrailingNewline(t *testing.T) {
	values := configmap.Values{"z": "last", "a": "first", "m": "middle"}

	got, err := values.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	want := "a=first\nm=middle\nz=last\n"
	if got != want {
		t.Fatalf("Encode() = %q, want %q", got, want)
	}
}

func TestCloneIsIndependent(t *testing.T) {
	original := configmap.Values{"key": "original"}
	clone := original.Clone()

	if err := clone.Set("key", "changed"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	if err := clone.Set("new", "value"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}

	want := configmap.Values{"key": "original"}
	if !reflect.DeepEqual(original, want) {
		t.Fatalf("original = %#v, want %#v", original, want)
	}
}

func TestSetReplacesAndDeleteRemoves(t *testing.T) {
	values := configmap.Values{"key": "old", "remove": "value"}

	if err := values.Set("key", "new"); err != nil {
		t.Fatalf("Set() error = %v", err)
	}
	values.Delete("remove")

	want := configmap.Values{"key": "new"}
	if !reflect.DeepEqual(values, want) {
		t.Fatalf("values = %#v, want %#v", values, want)
	}
}

func TestParseEmptyInput(t *testing.T) {
	values, err := configmap.Parse("")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(values) != 0 {
		t.Fatalf("len(Parse()) = %d, want 0", len(values))
	}

	encoded, err := values.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if encoded != "" {
		t.Fatalf("Encode() = %q, want empty string", encoded)
	}
}

func TestParseRejectsMalformedInput(t *testing.T) {
	tests := map[string]string{
		"duplicate key":     "key=one\nkey=two",
		"empty key":         "=value",
		"missing separator": "key",
		"carriage return":   "key=value\rmore",
		"extra final line":  "key=value\n\n",
	}

	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := configmap.Parse(encoded); err == nil {
				t.Fatal("Parse() error = nil, want error")
			}
		})
	}
}

func TestSetRejectsInvalidRecords(t *testing.T) {
	tests := map[string]struct {
		key   string
		value string
	}{
		"empty key":             {key: "", value: "value"},
		"separator in key":      {key: "bad=key", value: "value"},
		"newline in key":        {key: "bad\nkey", value: "value"},
		"carriage return key":   {key: "bad\rkey", value: "value"},
		"newline in value":      {key: "key", value: "bad\nvalue"},
		"carriage return value": {key: "key", value: "bad\rvalue"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			values := configmap.Values{}
			if err := values.Set(test.key, test.value); err == nil {
				t.Fatal("Set() error = nil, want error")
			}
			if len(values) != 0 {
				t.Fatalf("Set() changed values to %#v", values)
			}
		})
	}
}

func TestEncodeRejectsInvalidMap(t *testing.T) {
	tests := map[string]configmap.Values{
		"empty key":        {"": "value"},
		"separator in key": {"bad=key": "value"},
		"newline in key":   {"bad\nkey": "value"},
		"newline in value": {"key": "bad\nvalue"},
	}

	for name, values := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := values.Encode(); err == nil {
				t.Fatal("Encode() error = nil, want error")
			}
		})
	}
}
