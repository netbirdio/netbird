package errors

import "fmt"

// Configuration errors

func NewConfigInvalid(message string) *AppError {
	return New(CodeConfigInvalid, message)
}

func NewConfigNotFound(path string) *AppError {
	return New(CodeConfigNotFound, fmt.Sprintf("configuration file not found: %s", path))
}

func WrapConfigParseFailed(err error, path string) *AppError {
	return Wrap(CodeConfigParseFailed, fmt.Sprintf("failed to parse configuration file: %s", path), err)
}

// Server errors

func NewServerStartFailed(err error, reason string) *AppError {
	return Wrap(CodeServerStartFailed, fmt.Sprintf("server start failed: %s", reason), err)
}

func NewServerStopFailed(err error) *AppError {
	return Wrap(CodeServerStopFailed, "server shutdown failed", err)
}

func NewServerAlreadyRunning() *AppError {
	return New(CodeServerAlreadyRunning, "server is already running")
}

func NewServerNotRunning() *AppError {
	return New(CodeServerNotRunning, "server is not running")
}

// Proxy errors

func NewProxyBackendUnavailable(backend string, err error) *AppError {
	return Wrap(CodeProxyBackendUnavailable, fmt.Sprintf("backend unavailable: %s", backend), err)
}

func NewProxyTimeout(backend string) *AppError {
	return New(CodeProxyTimeout, fmt.Sprintf("request to backend timed out: %s", backend))
}

func NewProxyInvalidTarget(target string, err error) *AppError {
	return Wrap(CodeProxyInvalidTarget, fmt.Sprintf("invalid proxy target: %s", target), err)
}

// Network errors

func NewNetworkTimeout(operation string) *AppError {
	return New(CodeNetworkTimeout, fmt.Sprintf("network timeout: %s", operation))
}

func NewNetworkUnreachable(host string) *AppError {
	return New(CodeNetworkUnreachable, fmt.Sprintf("network unreachable: %s", host))
}

func NewNetworkRefused(host string) *AppError {
	return New(CodeNetworkRefused, fmt.Sprintf("connection refused: %s", host))
}

// Internal errors

func NewInternalError(message string) *AppError {
	return New(CodeInternalError, message)
}

func WrapInternalError(err error, message string) *AppError {
	return Wrap(CodeInternalError, message, err)
}
