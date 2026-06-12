//go:build !android && !ios && !freebsd && !js

package main

import (
	"strings"

	"github.com/wailsapp/wails/v3/pkg/application"

	"github.com/netbirdio/netbird/client/ui/services"
)

func (t *Tray) onStatusEvent(ev *application.CustomEvent) {
	st, ok := ev.Data.(services.Status)
	if !ok {
		return
	}
	t.applyStatus(st)
}

// applyStatus updates the tray icon, status label, exit-node submenu, and
// connect/disconnect enablement based on the latest daemon snapshot.
// Skips the icon refresh when none of the icon-relevant inputs
// (connected, hasUpdate, status label) changed — the daemon emits
// rapid SubscribeStatus bursts during health probes that would
// otherwise spam Shell_NotifyIcon and the log.
//
// Profile-switch suppression lives one layer up in services/daemon_feed.go
// (DaemonFeed.BeginProfileSwitch / consumeForSwitch) so the optimistic
// Connecting paint and the suppressed Idle/Connected events are shared
// with the React Status page rather than being a tray-only behaviour.
func (t *Tray) applyStatus(st services.Status) {
	t.statusMu.Lock()
	connected := strings.EqualFold(st.Status, services.StatusConnected)
	iconChanged := connected != t.connected || st.Status != t.lastStatus
	// Detect the transition into SessionExpired: the daemon emits the
	// state on every Status snapshot for as long as the session stays
	// expired, so without this guard we would re-fire the notification
	// on every push. Mirrors the legacy Fyne client's sendNotification
	// flag in onSessionExpire.
	sessionExpiredEnter := strings.EqualFold(st.Status, services.StatusSessionExpired) &&
		!strings.EqualFold(t.lastStatus, services.StatusSessionExpired)

	triggerLogin := t.consumePendingConnectLogin(st.Status)

	daemonVersionChanged := st.DaemonVersion != "" && st.DaemonVersion != t.lastDaemonVersion
	t.connected = connected
	t.lastStatus = st.Status
	if daemonVersionChanged {
		t.lastDaemonVersion = st.DaemonVersion
	}

	revisionChanged := st.NetworksRevision != t.lastNetworksRevision
	t.lastNetworksRevision = st.NetworksRevision
	t.statusMu.Unlock()

	if triggerLogin {
		t.app.Event.Emit(services.EventTriggerLogin)
	}

	// Cache-only; the row is painted by the relayout below.
	sessionChanged := t.applySessionExpiry(st.SessionExpiresAt, connected)

	if iconChanged {
		t.applyIcon()
	}
	// All repainting goes through relayoutMenu (menuMu-serialised, paints
	// from the caches committed above): applyStatus runs concurrently with
	// itself and with relayouts (Wails dispatches listeners on fresh
	// goroutines), so in-place item mutation here would race the buildMenu
	// pointer swap.
	if iconChanged || daemonVersionChanged || sessionChanged {
		t.relayoutMenu()
	}
	// Re-fetch the selectable exit-node list whenever the daemon's routed-
	// networks revision bumps (a route candidate added/removed, or a selection
	// applied from any surface) or the tunnel flips state (iconChanged). The
	// revision is the only reliable signal: candidate routes never appear in
	// the peer-status snapshot, so a removed exit node would otherwise go
	// unnoticed. The refresh owns the parent item's enablement and the rebuild.
	if iconChanged || revisionChanged {
		go t.refreshExitNodes()
	}
	// The daemon emits no active-profile event, so profile flips driven
	// elsewhere (CLI, autoconnect) surface via status transitions.
	if iconChanged {
		go t.loadProfiles()
	}
	if sessionExpiredEnter {
		t.handleSessionExpired()
	}
}

// consumePendingConnectLogin acts on the SSO auto-handoff flag armed by
// handleConnect. It returns true (and clears the flag) when the daemon
// reached NeedsLogin, signalling the browser-login flow should start so the
// user doesn't need to click Connect a second time. The flag is also cleared
// on any other terminal state — including Connecting bursts that resolve to
// Connected / Idle / LoginFailed / DaemonUnavailable — so a stale flag can't
// fire weeks later when the daemon happens to flip. Must be called with
// statusMu held.
func (t *Tray) consumePendingConnectLogin(status string) bool {
	if !t.pendingConnectLogin {
		return false
	}
	switch {
	case strings.EqualFold(status, services.StatusNeedsLogin):
		t.pendingConnectLogin = false
		return true
	case strings.EqualFold(status, services.StatusConnected),
		strings.EqualFold(status, services.StatusIdle),
		strings.EqualFold(status, services.StatusLoginFailed),
		strings.EqualFold(status, services.StatusSessionExpired),
		strings.EqualFold(status, services.StatusDaemonUnavailable):
		t.pendingConnectLogin = false
	}
	return false
}

// applyStatusIndicator sets the coloured status dot. Called only from
// relayoutMenu (menuMu held): on macOS the bitmap repaints via the
// relayout's trailing SetMenu — no SetMenu here, the tree is half-built.
func (t *Tray) applyStatusIndicator(status string) {
	if t.statusItem == nil {
		return
	}
	t.statusItem.SetBitmap(statusIndicatorBitmap(status))
}

func statusIndicatorBitmap(status string) []byte {
	switch {
	case strings.EqualFold(status, services.StatusConnected):
		return iconMenuDotConnected
	case strings.EqualFold(status, services.StatusConnecting):
		return iconMenuDotConnecting
	case strings.EqualFold(status, services.StatusNeedsLogin),
		strings.EqualFold(status, services.StatusSessionExpired):
		return iconMenuDotConnecting
	case strings.EqualFold(status, services.StatusLoginFailed),
		strings.EqualFold(status, statusError):
		return iconMenuDotError
	case strings.EqualFold(status, services.StatusDaemonUnavailable):
		return iconMenuDotOffline
	default:
		return iconMenuDotIdle
	}
}
