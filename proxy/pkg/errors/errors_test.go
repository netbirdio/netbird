package errors

import (
	"errors"
	"testing"
)

func TestAppError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *AppError
		expected string
	}{
		{
			name:     "error without cause",
			err:      New(CodeConfigInvalid, "invalid configuration"),
			expected: "[CONFIG_INVALID] invalid configuration",
		},
		{
			name:     "error with cause",
			err:      Wrap(CodeServerStartFailed, "failed to bind port", errors.New("address already in use")),
			expected: "[SERVER_START_FAILED] failed to bind port: address already in use",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGetCode(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected Code
	}{
		{
			name:     "app error",
			err:      New(CodeConfigInvalid, "test"),
			expected: CodeConfigInvalid,
		},
		{
			name:     "wrapped app error",
			err:      Wrap(CodeServerStartFailed, "test", errors.New("cause")),
			expected: CodeServerStartFailed,
		},
		{
			name:     "standard error",
			err:      errors.New("standard error"),
			expected: CodeUnknownError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetCode(tt.err); got != tt.expected {
				t.Errorf("GetCode() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestHasCode(t *testing.T) {
	err := New(CodeConfigInvalid, "invalid config")

	if !HasCode(err, CodeConfigInvalid) {
		t.Error("HasCode() should return true for matching code")
	}

	if HasCode(err, CodeServerStartFailed) {
		t.Error("HasCode() should return false for non-matching code")
	}
}

func TestIsConfigError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "config invalid error",
			err:      New(CodeConfigInvalid, "test"),
			expected: true,
		},
		{
			name:     "config not found error",
			err:      New(CodeConfigNotFound, "test"),
			expected: true,
		},
		{
			name:     "server error",
			err:      New(CodeServerStartFailed, "test"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsConfigError(tt.err); got != tt.expected {
				t.Errorf("IsConfigError() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestErrorUnwrap(t *testing.T) {
	cause := errors.New("root cause")
	err := Wrap(CodeInternalError, "wrapped error", cause)

	unwrapped := errors.Unwrap(err)
	if unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestErrorIs(t *testing.T) {
	err1 := New(CodeConfigInvalid, "test1")
	err2 := New(CodeConfigInvalid, "test2")
	err3 := New(CodeServerStartFailed, "test3")

	if !errors.Is(err1, err2) {
		t.Error("errors.Is() should return true for same error code")
	}

	if errors.Is(err1, err3) {
		t.Error("errors.Is() should return false for different error codes")
	}
}

func TestCommonConstructors(t *testing.T) {
	t.Run("NewConfigNotFound", func(t *testing.T) {
		err := NewConfigNotFound("/path/to/config")
		if GetCode(err) != CodeConfigNotFound {
			t.Error("NewConfigNotFound should create CONFIG_NOT_FOUND error")
		}
	})

	t.Run("NewServerAlreadyRunning", func(t *testing.T) {
		err := NewServerAlreadyRunning()
		if GetCode(err) != CodeServerAlreadyRunning {
			t.Error("NewServerAlreadyRunning should create SERVER_ALREADY_RUNNING error")
		}
	})

	t.Run("NewProxyBackendUnavailable", func(t *testing.T) {
		cause := errors.New("connection refused")
		err := NewProxyBackendUnavailable("http://backend", cause)
		if GetCode(err) != CodeProxyBackendUnavailable {
			t.Error("NewProxyBackendUnavailable should create PROXY_BACKEND_UNAVAILABLE error")
		}
		if !errors.Is(err.Unwrap(), cause) {
			t.Error("NewProxyBackendUnavailable should wrap the cause")
		}
	})
}
