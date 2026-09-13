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
	// BaselineRequired indicates that complete persisted configuration is absent.
	BaselineRequired ErrorCode = "baseline_required"
	// BaselineUnusable indicates that persisted configuration cannot support typed changes.
	BaselineUnusable ErrorCode = "baseline_unusable"
	// PolicyRequired indicates that a new resource lacks required operator policy.
	PolicyRequired ErrorCode = "policy_required"
	// ConfigurationPending indicates that a prior configuration has not been reported.
	ConfigurationPending ErrorCode = "configuration_pending"
	// ConfigurationDrift indicates that the device report differs from the baseline.
	ConfigurationDrift ErrorCode = "configuration_drift"
	// DesiredStateMissing indicates that typed desired state is unavailable.
	DesiredStateMissing ErrorCode = "desired_state_missing"
	// ResourceNotFound indicates that the selected typed resource is absent.
	ResourceNotFound ErrorCode = "resource_not_found"
	// ResourceExists indicates that a typed resource already uses the requested identity.
	ResourceExists ErrorCode = "resource_exists"
	// AmbiguousDevice indicates that device auto-selection was not unique.
	AmbiguousDevice ErrorCode = "ambiguous_device"
	// PreviewStale indicates that a preview no longer matches current inputs.
	PreviewStale ErrorCode = "preview_stale"
	// RequestFailed indicates an otherwise unclassified failure.
	RequestFailed ErrorCode = "request_failed"
)

// ControlError contains only an actionable code and optional configuration field.
type ControlError struct {
	Code  ErrorCode `json:"code"`
	Field string    `json:"field,omitempty"`
}

var safeField = regexp.MustCompile(`^(country_code|networks|radios|ports|ssh(\.(username|password))?|radios\[[0-9]{1,6}\](\.(id|band|enabled|channel|width_mhz|power(\.(mode|dbm))?))?|networks\[[0-9]{1,6}\](\.(name|enabled|vlan|bands(\[[0-9]{1,6}\])?|radio_ids(\[[0-9]{1,6}\])?|bss_transition|security(\.(mode|psk))?))?|ports\[[0-9]{1,6}\](\.(index|enabled|native_vlan|tagged_vlans(\[[0-9]{1,6}\])?|poe))?)$`)

// Error renders the safe category and field without underlying values.
func (failure *ControlError) Error() string {
	code := failure.Code
	switch code {
	case InvalidDevice, NotRegistered, NoReport, FamilyMismatch, AdoptionPending, InvalidConfig, InvalidEncoding, FileReadFailed, PersistenceFailed, EncodingFailed, ObservationUnavailable, BaselineRequired, BaselineUnusable, PolicyRequired, ConfigurationPending, ConfigurationDrift, DesiredStateMissing, ResourceNotFound, ResourceExists, AmbiguousDevice, PreviewStale, RequestFailed:
	default:
		code = RequestFailed
	}
	if safeField.MatchString(failure.Field) {
		return string(code) + ": " + failure.Field
	}
	return string(code)
}
