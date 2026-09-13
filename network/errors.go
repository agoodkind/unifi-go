package network

import "regexp"

// ErrorCode identifies a safe controller failure category.
type ErrorCode string

const (
	// InvalidDevice indicates an invalid device identifier.
	InvalidDevice ErrorCode = "invalid_device"
	// NotRegistered indicates a missing registered identity.
	NotRegistered ErrorCode = "not_registered"
	// NoReport indicates that a fresh inform is required.
	NoReport ErrorCode = "no_report"
	// FamilyMismatch indicates a conflicting device family.
	FamilyMismatch ErrorCode = "family_mismatch"
	// AdoptionPending indicates an unfinished inform key transition.
	AdoptionPending ErrorCode = "adoption_pending"
	// InvalidConfig indicates unsupported or invalid configuration.
	InvalidConfig ErrorCode = "invalid_config"
	// InvalidEncoding indicates text that cannot cross the JSON control transport.
	InvalidEncoding ErrorCode = "invalid_encoding"
	// FileReadFailed indicates an unreadable credential file.
	FileReadFailed ErrorCode = "credential_read"
	// PersistenceFailed indicates that desired state was not saved.
	PersistenceFailed ErrorCode = "persistence_failed"
	// EncodingFailed indicates configuration encoding failed.
	EncodingFailed ErrorCode = "encoding_failed"
	// ObservationUnavailable indicates that observations cannot be decoded.
	ObservationUnavailable ErrorCode = "observation_unavailable"
	// RequestFailed indicates an otherwise unclassified failure.
	RequestFailed ErrorCode = "request_failed"
)

// ControlError contains only an actionable code and optional configuration field.
type ControlError struct {
	Code  ErrorCode `json:"code"`
	Field string    `json:"field,omitempty"`
}

var safeField = regexp.MustCompile(`^(country_code|ssh\.(username|password)|radios\[[0-9]{1,6}\](\.(band|enabled|channel|width_mhz|power\.(mode|dbm)))?|networks\[[0-9]{1,6}\](\.(name|enabled|vlan|bands(\[[0-9]{1,6}\])?|security\.(mode|psk)))?|ports\[[0-9]{1,6}\](\.(index|enabled|native_vlan|tagged_vlans(\[[0-9]{1,6}\])?|poe))?)$`)

// Error renders the safe category and field without underlying values.
func (failure *ControlError) Error() string {
	code := failure.Code
	switch code {
	case InvalidDevice, NotRegistered, NoReport, FamilyMismatch, AdoptionPending, InvalidConfig, InvalidEncoding, FileReadFailed, PersistenceFailed, EncodingFailed, ObservationUnavailable, RequestFailed:
	default:
		code = RequestFailed
	}
	if safeField.MatchString(failure.Field) {
		return string(code) + ": " + failure.Field
	}
	return string(code)
}
