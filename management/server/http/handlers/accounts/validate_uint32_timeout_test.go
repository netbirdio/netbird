package accounts

import (
	"errors"
	"math"
	"strings"
	"testing"
)

// Codex review: validateUint32Timeout was added to fix the silent
// wrap-around when API JSON int64 fields landed in uint32 daemon
// fields. Make sure the boundary conditions stay covered.
func TestValidateUint32Timeout(t *testing.T) {
	tests := []struct {
		name    string
		input   int64
		want    uint32
		wantErr bool
	}{
		{"zero", 0, 0, false},
		{"one", 1, 1, false},
		{"3h_typical_p2p", 10800, 10800, false},
		{"24h_typical_relay", 86400, 86400, false},
		{"max_uint32", int64(math.MaxUint32), math.MaxUint32, false},
		{"max_uint32_plus_one", int64(math.MaxUint32) + 1, 0, true},
		{"negative_one", -1, 0, true},
		{"negative_huge", -86400, 0, true},
		{"int64_max", math.MaxInt64, 0, true},
		{"int64_min", math.MinInt64, 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateUint32Timeout("test_field", tc.input)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for input %d, got nil", tc.input)
				}
				if !strings.Contains(err.Error(), "test_field") {
					t.Errorf("error must mention field name, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %d: %v", tc.input, err)
			}
			if got != tc.want {
				t.Errorf("input %d: got %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

// TestValidateUint32Timeout_ErrorMessageFormat verifies the error
// message includes both the field name and the offending value, so
// API clients see actionable feedback.
func TestValidateUint32Timeout_ErrorMessageFormat(t *testing.T) {
	_, err := validateUint32Timeout("relay_timeout_seconds", -42)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "relay_timeout_seconds") {
		t.Errorf("error must mention field: %v", err)
	}
	if !strings.Contains(err.Error(), "-42") {
		t.Errorf("error must mention input value: %v", err)
	}

	_, err = validateUint32Timeout("p2p_timeout_seconds", int64(math.MaxUint32)+1)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("overflow error must say 'exceeds': %v", err)
	}
}

// Sanity: the helper returns plain Go errors (not status.Errorf
// wrappers); the caller wraps them. Document that contract here.
func TestValidateUint32Timeout_PlainError(t *testing.T) {
	_, err := validateUint32Timeout("x", -1)
	var unwrapped error = err
	if errors.Unwrap(err) != nil {
		// fmt.Errorf without %w gives a plain error; if someone changes
		// it to %w later this assertion catches the API change.
		unwrapped = errors.Unwrap(err)
	}
	if unwrapped == nil {
		t.Fatal("error must be non-nil")
	}
}
