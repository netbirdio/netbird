package sessionwatch

import (
	"strconv"
	"time"
)

// internal event kinds are no longer exposed: the watcher drives the Sink
// directly (NotifyStateChange on deadline change/clear, PublishEvent at
// each warning lead). Tests use a mock Sink to observe what the watcher
// emits.

// Metadata keys attached by the daemon to session-warning SystemEvents.
// The UI tray reads these to build a locale-aware notification without
// relying on the daemon's locale-less UserMessage string, and to
// disambiguate the T-WarningLead notification from the T-FinalWarningLead
// fallback that auto-opens the SessionAboutToExpire dialog.
const (
	// MetaSessionWarning is set to "true" on both warning events (T-10 and
	// T-2) so the UI can detect a session-warning SystemEvent without
	// matching on the message text. Use MetaSessionFinal to distinguish
	// the two.
	MetaSessionWarning = "session_warning"
	// MetaSessionFinal is set to "true" on the T-FinalWarningLead event
	// only. Consumers that need to auto-open the SessionAboutToExpire
	// dialog gate on this; T-WarningLead events leave the field unset.
	MetaSessionFinal = "session_final_warning"
	// MetaSessionExpiresAt carries the absolute UTC deadline encoded with
	// FormatExpiresAt; consumers must decode with ParseExpiresAt so a
	// future format change stays a single edit.
	MetaSessionExpiresAt = "session_expires_at"
	// MetaSessionLeadMinutes carries the lead in whole minutes (WarningLead
	// for the T-10 event, FinalWarningLead for the T-2 event) so the UI
	// can show "expires in ~N minutes" without hardcoding either constant.
	MetaSessionLeadMinutes = "lead_minutes"
	// MetaSessionDeadlineRejected is attached to the ERROR/AUTHENTICATION
	// SystemEvent the daemon emits when it discards a deadline from the
	// management server (pre-epoch, too far in the future, or past the
	// clock-skew tolerance). The value is the rejection reason string.
	// userMessage is left empty; the UI detects the event via this key
	// and builds a localized notification — same pattern as the session
	// warnings above.
	MetaSessionDeadlineRejected = "session_deadline_rejected"
)

// expiresAtLayout is the wire format used for MetaSessionExpiresAt.
// Producer and consumers both go through FormatExpiresAt/ParseExpiresAt
// so this layout stays a single source of truth.
const expiresAtLayout = time.RFC3339

// FormatExpiresAt encodes a deadline for MetaSessionExpiresAt. Always
// emits UTC so a consumer in another timezone reads the same wall-clock
// deadline.
func FormatExpiresAt(t time.Time) string {
	return t.UTC().Format(expiresAtLayout)
}

// ParseExpiresAt decodes the MetaSessionExpiresAt value back to a UTC
// time. Returns an error when the field is empty or malformed; the
// caller decides whether to fall back (zero value) or propagate.
func ParseExpiresAt(s string) (time.Time, error) {
	t, err := time.Parse(expiresAtLayout, s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

// FormatLeadMinutes encodes a lead duration for MetaSessionLeadMinutes
// as the integer count of whole minutes. Sub-minute residuals are
// truncated — the field is informational ("expires in ~N minutes") and
// fractional minutes don't change what the UI displays.
func FormatLeadMinutes(d time.Duration) string {
	return strconv.Itoa(int(d / time.Minute))
}

// ParseLeadMinutes decodes a MetaSessionLeadMinutes value. Returns 0
// and the parse error for malformed input; consumers that prefer a
// silent fallback can simply ignore the error.
func ParseLeadMinutes(s string) (int, error) {
	return strconv.Atoi(s)
}
