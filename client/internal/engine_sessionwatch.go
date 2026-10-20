//go:build !js && !android

package internal

import (
	"github.com/netbirdio/netbird/client/internal/auth/sessionwatch"
	"github.com/netbirdio/netbird/client/internal/peer"
)

// newSessionWatcher returns the real SSO session expiry watcher. The js/wasm
// build gets a no-op stub from engine_sessionwatch_js.go so the sessionwatch
// package (and its timer machinery) never links into the wasm binary; the
// android build gets a deadline-only watcher from
// engine_sessionwatch_android.go because the app schedules the warnings
// itself.
func newSessionWatcher(recorder *peer.Status) sessionDeadlineWatcher {
	return sessionwatch.New(recorder)
}
