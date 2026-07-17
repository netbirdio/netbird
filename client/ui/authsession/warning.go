//go:build !android && !ios && !freebsd && !js

// Package authsession holds the UI-side domain logic for the SSO
// session-extend feature. The Wails facades in client/ui/services/session*.go
// are thin adapters over these types.
package authsession

import (
	"time"

	"github.com/netbirdio/netbird/client/internal/auth/sessionwatch"
)

// Re-exported from sessionwatch so UI-side consumers don't import the
// daemon-internal package directly.
const (
	MetaWarning          = sessionwatch.MetaSessionWarning
	MetaFinal            = sessionwatch.MetaSessionFinal
	MetaExpiresAt        = sessionwatch.MetaSessionExpiresAt
	MetaLeadMinutes      = sessionwatch.MetaSessionLeadMinutes
	MetaDeadlineRejected = sessionwatch.MetaSessionDeadlineRejected
)

// Warning is the typed payload emitted on the session-warning Wails events.
type Warning struct {
	// Absolute UTC deadline; best-effort, stays zero when metadata is
	// missing or malformed (e.g. an older daemon) and the UI falls back
	// to the Status snapshot.
	ExpiresAt time.Time `json:"sessionExpiresAt"`
	// Configured lead time, so the UI need not hardcode the constant.
	LeadMinutes int `json:"leadMinutes"`
	// True on the final-warning fallback event.
	Final bool `json:"final"`
}

// WarningFromMetadata parses SystemEvent metadata into a Warning, or returns
// (nil, false) when the event is not a session-warning. A field that fails to
// parse stays zero; the event is still surfaced.
func WarningFromMetadata(meta map[string]string) (*Warning, bool) {
	if meta == nil || meta[MetaWarning] != "true" {
		return nil, false
	}

	out := &Warning{
		Final: meta[MetaFinal] == "true",
	}
	if raw := meta[MetaExpiresAt]; raw != "" {
		if t, err := sessionwatch.ParseExpiresAt(raw); err == nil {
			out.ExpiresAt = t
		}
	}
	if raw := meta[MetaLeadMinutes]; raw != "" {
		if n, err := sessionwatch.ParseLeadMinutes(raw); err == nil {
			out.LeadMinutes = n
		}
	}
	return out, true
}

// ParseExpiresAt re-exports sessionwatch.ParseExpiresAt so UI-side call sites
// don't import the daemon-internal package.
func ParseExpiresAt(s string) (time.Time, error) {
	return sessionwatch.ParseExpiresAt(s)
}
