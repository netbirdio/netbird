//go:build !android && !ios && !freebsd && !js

package authsession

import (
	"testing"
	"time"
)

func TestWarningFromMetadata_NotASessionWarning(t *testing.T) {
	cases := []struct {
		name string
		meta map[string]string
	}{
		{"nil metadata", nil},
		{"empty map", map[string]string{}},
		{"unrelated event", map[string]string{"new_version_available": "0.65.0"}},
		{"flag not 'true'", map[string]string{"session_warning": "1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if w, ok := WarningFromMetadata(tc.meta); ok {
				t.Fatalf("expected (nil, false), got (%+v, %v)", w, ok)
			}
		})
	}
}

func TestWarningFromMetadata_FullPayload(t *testing.T) {
	ts := "2026-05-18T13:30:00Z"
	meta := map[string]string{
		"session_warning":    "true",
		"session_expires_at": ts,
		"lead_minutes":       "10",
	}

	got, ok := WarningFromMetadata(meta)
	if !ok {
		t.Fatalf("expected the warning to be recognised, got ok=false")
	}
	want, _ := time.Parse(time.RFC3339, ts)
	if !got.ExpiresAt.Equal(want.UTC()) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, want.UTC())
	}
	if got.LeadMinutes != 10 {
		t.Errorf("LeadMinutes = %d, want 10", got.LeadMinutes)
	}
}

func TestWarningFromMetadata_BadFieldsStillEmits(t *testing.T) {
	// Older or buggy daemon: the flag is set but the timestamp/lead are
	// missing or malformed. The UI should still get a warning so it can
	// at least surface "session expires soon"; field zero-values are fine.
	meta := map[string]string{
		"session_warning":    "true",
		"session_expires_at": "not-a-timestamp",
		"lead_minutes":       "abc",
	}

	got, ok := WarningFromMetadata(meta)
	if !ok {
		t.Fatalf("warning should still be recognised even with malformed fields")
	}
	if !got.ExpiresAt.IsZero() {
		t.Errorf("malformed timestamp should leave field zero, got %v", got.ExpiresAt)
	}
	if got.LeadMinutes != 0 {
		t.Errorf("malformed lead_minutes should leave field 0, got %d", got.LeadMinutes)
	}
}

func TestWarningFromMetadata_MissingFieldsStillEmits(t *testing.T) {
	// Only the flag is present (e.g. future-trimmed event). Still emit.
	meta := map[string]string{"session_warning": "true"}
	got, ok := WarningFromMetadata(meta)
	if !ok {
		t.Fatalf("warning should still be recognised when only flag is present")
	}
	if got.ExpiresAt.IsZero() != true || got.LeadMinutes != 0 {
		t.Errorf("missing fields should be zero-valued, got %+v", got)
	}
}
