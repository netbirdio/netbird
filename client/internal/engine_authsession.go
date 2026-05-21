package internal

import (
	"context"
	"errors"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/netbirdio/netbird/client/system"
)

// ApplySessionDeadline propagates the absolute SSO session deadline carried on
// LoginResponse / SyncResponse to both the watcher (for the edge-triggered
// warning) and the status recorder (for the SubscribeStatus / Status RPC
// snapshot the UI consumes).
//
// The wire field is 3-state:
//   - nil                        → snapshot carries no info; keep the
//     previously-anchored deadline (no-op)
//   - explicit zero (s=0, n=0)   → peer is not SSO-registered or expiry is
//     disabled; clear both sinks
//   - valid timestamp            → new deadline; arm watcher, expose on
//     status recorder
//
// Deadline sanity-checks live in sessionwatch.Watcher.Update. Any rejected
// value is treated as a clear on both sinks: the alternative — leaving the
// previously-known deadline in place — risks the UI confidently displaying
// a stale "expires in X" while the server has actually invalidated it.
func (e *Engine) ApplySessionDeadline(ts *timestamppb.Timestamp) {
	if ts == nil {
		return
	}
	var deadline time.Time
	// Explicit zero (seconds=0 AND nanos=0) is the sentinel for "disabled".
	// Everything else flows through Watcher.Update, whose sanity-checks
	// reject out-of-range / pre-epoch / far-future / too-stale values; the
	// catch-block below converts any rejection into a clear.
	if ts.GetSeconds() != 0 || ts.GetNanos() != 0 {
		deadline = ts.AsTime().UTC()
	}
	if e.sessionWatcher != nil {
		if err := e.sessionWatcher.Update(deadline); err != nil {
			log.Errorf("auth session deadline rejected: %v, clearing", err)
			deadline = time.Time{}
		}
	}
	if e.statusRecorder != nil {
		e.statusRecorder.SetSessionExpiresAt(deadline)
	}
}

// DismissSessionWarning records the user's "Dismiss" click on the
// T-WarningLead interactive notification and suppresses the upcoming
// T-FinalWarningLead fallback for the current deadline. No-op when the
// watcher is not running or holds no deadline.
func (e *Engine) DismissSessionWarning() {
	if e.sessionWatcher == nil {
		return
	}
	e.sessionWatcher.Dismiss()
}

// ExtendAuthSession asks the management server to refresh the SSO session
// expiry deadline using the supplied JWT, then mirrors the new deadline into
// the daemon's state. The tunnel is untouched; no resync, no reconnect.
//
// Returns the new absolute UTC deadline (or zero time when the server
// reports the peer is not eligible for extension).
func (e *Engine) ExtendAuthSession(ctx context.Context, jwtToken string) (time.Time, error) {
	if jwtToken == "" {
		return time.Time{}, errors.New("jwt token is required")
	}
	if e.mgmClient == nil {
		return time.Time{}, errors.New("management client is not initialised")
	}

	info, err := system.GetInfoWithChecks(ctx, e.checks)
	if err != nil {
		log.Warnf("failed to collect system info for session extend: %v", err)
		info = system.GetInfo(ctx)
	}

	resp, err := e.mgmClient.ExtendAuthSession(info, jwtToken)
	if err != nil {
		return time.Time{}, fmt.Errorf("extend auth session on management: %w", err)
	}

	e.ApplySessionDeadline(resp.GetSessionExpiresAt())

	if resp.GetSessionExpiresAt().IsValid() {
		return resp.GetSessionExpiresAt().AsTime().UTC(), nil
	}
	return time.Time{}, nil
}
