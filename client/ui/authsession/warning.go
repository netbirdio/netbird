//go:build !android && !ios && !freebsd && !js

// Package authsession holds the UI-side domain logic for the SSO
// session-extend feature. Wails service facades in
// client/ui/services/session*.go are thin adapters around the types and
// functions defined here; the parsing, request shapes, and constants
// live in this package so future-us can reason about (and test) the
// feature without dragging the Wails service surface around with it.
package authsession

import (
	"time"

	"github.com/netbirdio/netbird/client/internal/auth/sessionwatch"
)

// Metadata keys the daemon attaches to session-warning SystemEvents.
// Re-exported from sessionwatch (single source of truth on the daemon
// side) so UI-side consumers don't have to import the daemon-internal
// package directly.
const (
	MetaWarning     = sessionwatch.MetaSessionWarning
	MetaFinal       = sessionwatch.MetaSessionFinal
	MetaExpiresAt   = sessionwatch.MetaSessionExpiresAt
	MetaLeadMinutes = sessionwatch.MetaSessionLeadMinutes
)

// Warning is the typed payload emitted on the session-warning Wails
// events. The React side subscribes to "netbird:session:warning" and
// "netbird:session:final-warning" and receives this shape.
//
// ExpiresAt is best-effort: when the metadata is missing or malformed
// (e.g. an older daemon emits the event without the timestamp) it stays
// zero — the UI can fall back to the Status snapshot.
type Warning struct {
	// ExpiresAt is the absolute UTC deadline the warning was fired
	// against. The UI displays remaining time relative to its own clock.
	ExpiresAt time.Time `json:"sessionExpiresAt"`
	// LeadMinutes is the warning's configured lead time in minutes
	// (WarningLead for the T-10 event, FinalWarningLead for the T-2
	// event). Exposed so the UI can show "expires in ~N minutes" without
	// hardcoding either constant on its side.
	LeadMinutes int `json:"leadMinutes"`
	// Final is true on the T-FinalWarningLead fallback event and false
	// on the regular T-WarningLead notification. Exposed so a frontend
	// listener bound to the dedicated final-warning Wails event still
	// receives a payload it can self-describe (and so a tray that
	// happens to see both event streams can branch in one place).
	Final bool `json:"final"`
}

// WarningFromMetadata parses the daemon's SystemEvent metadata into a
// Warning payload. Returns (nil, false) when the event is not a
// session-warning at all (the common case). When the metadata flag is
// set but a field fails to parse, the field stays at its zero value and
// the event is still surfaced — the UI gets to decide how to handle it.
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

// ParseExpiresAt decodes a MetaExpiresAt metadata value to a UTC time.
// Thin re-export of sessionwatch.ParseExpiresAt so UI-side call sites
// (tray, frontend bindings) don't import the daemon-internal package.
func ParseExpiresAt(s string) (time.Time, error) {
	return sessionwatch.ParseExpiresAt(s)
}
