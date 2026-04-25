package entra_device

import (
	"errors"
	"fmt"
	"net/http"
)

// ErrorCode is a stable, machine-readable code returned to the client so that
// automation (the NetBird client, Intune, scripts) can dispatch on specific
// failure modes.
type ErrorCode string

const (
	CodeIntegrationNotFound   ErrorCode = "integration_not_found"
	CodeIntegrationDisabled   ErrorCode = "integration_disabled"
	CodeInvalidNonce          ErrorCode = "invalid_nonce"
	CodeInvalidCertChain      ErrorCode = "invalid_cert_chain"
	CodeInvalidSignature      ErrorCode = "invalid_signature"
	CodeDeviceDisabled        ErrorCode = "device_disabled"
	CodeDeviceNotCompliant    ErrorCode = "device_not_compliant"
	CodeNoDeviceCertForTenant ErrorCode = "no_device_cert_for_tenant"
	CodeNoMappingMatched      ErrorCode = "no_mapping_matched"
	CodeAllMappingsRevoked    ErrorCode = "all_mappings_revoked"
	CodeAllMappingsExpired    ErrorCode = "all_mappings_expired"
	CodeGroupLookupFailed     ErrorCode = "group_lookup_unavailable"
	CodeInternal              ErrorCode = "internal_error"
	CodeAlreadyEnrolled       ErrorCode = "already_enrolled"
)

// Error wraps an ErrorCode together with an optional underlying error and a
// suitable HTTP status for the client.
type Error struct {
	Code       ErrorCode
	HTTPStatus int
	Message    string
	Cause      error
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the wrapped underlying error.
func (e *Error) Unwrap() error { return e.Cause }

// NewError produces an Error with the proper HTTP status for the given code.
func NewError(code ErrorCode, message string, cause error) *Error {
	return &Error{
		Code:       code,
		HTTPStatus: statusFor(code),
		Message:    message,
		Cause:      cause,
	}
}

// AsError extracts an *Error from err if possible.
func AsError(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

func statusFor(code ErrorCode) int {
	switch code {
	case CodeIntegrationNotFound:
		return http.StatusNotFound
	case CodeIntegrationDisabled,
		CodeDeviceDisabled,
		CodeDeviceNotCompliant,
		CodeNoDeviceCertForTenant,
		CodeNoMappingMatched,
		CodeAllMappingsRevoked,
		CodeAllMappingsExpired:
		return http.StatusForbidden
	case CodeInvalidNonce,
		CodeInvalidCertChain,
		CodeInvalidSignature:
		return http.StatusUnauthorized
	case CodeGroupLookupFailed:
		return http.StatusServiceUnavailable
	case CodeAlreadyEnrolled:
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}
