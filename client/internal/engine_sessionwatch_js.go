//go:build js

package internal

import (
	"time"

	"github.com/netbirdio/netbird/client/internal/peer"
)

// noopSessionWatcher is the js/wasm stand-in for sessionwatch.Watcher. The
// wasm client never runs the engine's session-warning flow (the interactive
// T-WarningLead notification and the T-FinalWarningLead fallback dialog live
// in the desktop UI), so linking the full sessionwatch package (timers, event
// composition) would only bloat the binary.
//
// It still mirrors the deadline into the status recorder so the SubscribeStatus
// / Status snapshot the UI consumes stays correct — only the timer-driven
// warnings are dropped.
type noopSessionWatcher struct {
	recorder *peer.Status
}

func newSessionWatcher(recorder *peer.Status) sessionDeadlineWatcher {
	return noopSessionWatcher{recorder: recorder}
}

// Update mirrors the real watcher's recorder propagation without the timers or
// sanity-check sentinels: a valid deadline is exposed on the status snapshot,
// the zero time clears it.
func (w noopSessionWatcher) Update(deadline time.Time) error {
	if w.recorder != nil {
		w.recorder.SetSessionExpiresAt(deadline)
	}
	return nil
}

func (noopSessionWatcher) Dismiss() {
	// No-op: only suppresses the timer-driven final-warning, which this stub never arms.
}

func (noopSessionWatcher) Close() {
	// No-op: no timers to stop and no state to unwind; the recorder is cleared via Update(zero).
}
