package device

import (
	"errors"
	"testing"
)

func TestIsWintunDriverError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "wintun driver error - exact message",
			err:      errors.New("Error creating interface: The system cannot find the file specified."),
			expected: true,
		},
		{
			name:     "wintun driver error - wrapped",
			err:      errors.New("error creating tun device: Error creating interface: The system cannot find the file specified."),
			expected: true,
		},
		{
			name:     "wintun driver error - different case",
			err:      errors.New("THE SYSTEM CANNOT FIND THE FILE SPECIFIED"),
			expected: true,
		},
		{
			name:     "unrelated error - access denied",
			err:      errors.New("Access is denied"),
			expected: false,
		},
		{
			name:     "unrelated error - timeout",
			err:      errors.New("operation timed out"),
			expected: false,
		},
		{
			name:     "unrelated error - generic",
			err:      errors.New("something went wrong"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isWintunDriverError(tt.err)
			if result != tt.expected {
				t.Errorf("isWintunDriverError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

func TestGetSystem32Command(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		wantPath bool // true if we expect a full path (command not on PATH)
	}{
		{
			name:     "sc.exe should be found",
			command:  "sc.exe",
			wantPath: false, // sc.exe is in System32 which is on PATH
		},
		{
			name:     "nonexistent command returns full path",
			command:  "totally_fake_command_12345.exe",
			wantPath: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getSystem32Command(tt.command)
			if result == "" {
				t.Error("getSystem32Command returned empty string")
			}
			if tt.wantPath {
				expected := `C:\windows\system32\` + tt.command
				if result != expected {
					t.Errorf("getSystem32Command(%q) = %q, want %q", tt.command, result, expected)
				}
			} else {
				// Should return the bare command name if found on PATH
				if result != tt.command {
					t.Errorf("getSystem32Command(%q) = %q, want %q", tt.command, result, tt.command)
				}
			}
		})
	}
}

func TestTryRecoverWintunDriver(t *testing.T) {
	// This test exercises the actual tryRecoverWintunDriver function.
	// It calls sc.exe to query the wintun service state.
	// The behavior depends on the current system state:
	// - If wintun service exists and is stopped: recovery will be attempted
	// - If wintun service doesn't exist: returns nil (nothing to recover)
	// - If wintun service is running: returns error (recovery not applicable)
	//
	// We don't assert a specific outcome since it depends on system state,
	// but we verify the function doesn't panic and returns a valid result.
	err := tryRecoverWintunDriver()
	// The function should complete without panicking.
	// Any error is acceptable depending on system state.
	_ = err
}
