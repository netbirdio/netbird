package errors

import (
	"errors"
	"fmt"
)

// Error codes for categorizing errors
type Code string

const (
	// Configuration errors
	CodeConfigInvalid     Code = "CONFIG_INVALID"
	CodeConfigNotFound    Code = "CONFIG_NOT_FOUND"
	CodeConfigParseFailed Code = "CONFIG_PARSE_FAILED"

	// Server errors
	CodeServerStartFailed    Code = "SERVER_START_FAILED"
	CodeServerStopFailed     Code = "SERVER_STOP_FAILED"
	CodeServerAlreadyRunning Code = "SERVER_ALREADY_RUNNING"
	CodeServerNotRunning     Code = "SERVER_NOT_RUNNING"

	// Proxy errors
	CodeProxyBackendUnavailable Code = "PROXY_BACKEND_UNAVAILABLE"
	CodeProxyTimeout            Code = "PROXY_TIMEOUT"
	CodeProxyInvalidTarget      Code = "PROXY_INVALID_TARGET"

	// Network errors
	CodeNetworkTimeout     Code = "NETWORK_TIMEOUT"
	CodeNetworkUnreachable Code = "NETWORK_UNREACHABLE"
	CodeNetworkRefused     Code = "NETWORK_REFUSED"

	// Internal errors
	CodeInternalError Code = "INTERNAL_ERROR"
	CodeUnknownError  Code = "UNKNOWN_ERROR"
)

// AppError represents a structured application error
type AppError struct {
	Code    Code   // Error code for categorization
	Message string // Human-readable error message
	Cause   error  // Underlying error (if any)
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap returns the underlying error (for errors.Is and errors.As)
func (e *AppError) Unwrap() error {
	return e.Cause
}

// Is checks if the error matches the target
func (e *AppError) Is(target error) bool {
	t, ok := target.(*AppError)
	if !ok {
		return false
	}
	return e.Code == t.Code
}

// New creates a new AppError
func New(code Code, message string) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
	}
}

// Wrap wraps an existing error with additional context
func Wrap(code Code, message string, cause error) *AppError {
	return &AppError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// Wrapf wraps an error with a formatted message
func Wrapf(code Code, cause error, format string, args ...interface{}) *AppError {
	return &AppError{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
		Cause:   cause,
	}
}

// GetCode extracts the error code from an error
func GetCode(err error) Code {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.Code
	}
	return CodeUnknownError
}

// HasCode checks if an error has a specific code
func HasCode(err error, code Code) bool {
	return GetCode(err) == code
}

// IsConfigError checks if an error is configuration-related
func IsConfigError(err error) bool {
	code := GetCode(err)
	return code == CodeConfigInvalid ||
		code == CodeConfigNotFound ||
		code == CodeConfigParseFailed
}

// IsServerError checks if an error is server-related
func IsServerError(err error) bool {
	code := GetCode(err)
	return code == CodeServerStartFailed ||
		code == CodeServerStopFailed ||
		code == CodeServerAlreadyRunning ||
		code == CodeServerNotRunning
}

// IsProxyError checks if an error is proxy-related
func IsProxyError(err error) bool {
	code := GetCode(err)
	return code == CodeProxyBackendUnavailable ||
		code == CodeProxyTimeout ||
		code == CodeProxyInvalidTarget
}

// IsNetworkError checks if an error is network-related
func IsNetworkError(err error) bool {
	code := GetCode(err)
	return code == CodeNetworkTimeout ||
		code == CodeNetworkUnreachable ||
		code == CodeNetworkRefused
}
