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

	if iconChanged {
		t.applyIcon()
		t.refreshMenuItemsForStatus(st, connected)
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
	if daemonVersionChanged && t.daemonVersionItem != nil {
		t.daemonVersionItem.SetLabel(t.loc.T("tray.menu.daemonVersion", "version", st.DaemonVersion))
	}
	if sessionExpiredEnter {
		t.handleSessionExpired()
	}

	t.applySessionExpiry(st.SessionExpiresAt, connected)
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

// refreshMenuItemsForStatus updates the status row, Connect/Disconnect
// enablement, Settings/Profiles gating, and Profiles submenu on a status-text
// transition (called from applyStatus only when iconChanged).
func (t *Tray) refreshMenuItemsForStatus(st services.Status, connected bool) {
	daemonUnavailable := strings.EqualFold(st.Status, services.StatusDaemonUnavailable)
	connecting := strings.EqualFold(st.Status, services.StatusConnecting)
	if t.statusItem != nil {
		// Label-only: row is informational (no OnClick). Enablement
		// is platform-dependent via statusRowEnabled — Windows
		// keeps it enabled so the Win32 disabled-state mask does
		// not desaturate the coloured dot; macOS/Linux disable it.
		// Swap the displayed text so the user sees a familiar
		// phrase instead of the raw daemon enum.
		t.statusItem.SetLabel(t.loc.StatusLabel(st.Status))
		t.statusItem.SetEnabled(statusRowEnabled())
		t.applyStatusIndicator(st.Status)
	}
	if t.upItem != nil {
		// Connect stays visible/clickable in NeedsLogin/SessionExpired/
		// LoginFailed too — the daemon's Up RPC kicks off the SSO flow
		// when re-auth is required, mirroring the legacy Fyne client
		// where the same button drove the initial and the re-login
		// paths. Hidden only when the action would be a no-op (tunnel
		// up, daemon mid-connect — Disconnect takes the slot) or
		// would fail with no useful side effect (daemon unreachable).
		t.upItem.SetHidden(connected || connecting || daemonUnavailable)
		t.upItem.SetEnabled(!connected && !connecting && !daemonUnavailable)
	}
	if t.downItem != nil {
		// Disconnect is the abort path while the daemon is still
		// retrying the management dial — without it the user has no
		// way to stop the loop short of killing the daemon.
		t.downItem.SetHidden(!connected && !connecting)
		t.downItem.SetEnabled(connected || connecting)
	}
	// Exit Node parent-item enablement (greyed unless the tunnel is up
	// AND at least one candidate exists) is owned by refreshExitNodes,
	// triggered by applyStatus on this same transition. Settings just needs
	// the daemon socket reachable.
	if t.settingsItem != nil {
		t.settingsItem.SetEnabled(!daemonUnavailable)
	}
	if t.profileSubmenuItem != nil {
		t.profileSubmenuItem.SetEnabled(!daemonUnavailable)
	}
	// Refresh the Profiles submenu on every status-text transition: the
	// daemon does not emit an active-profile event, so the startup race
	// (UI loads profiles before autoconnect picks the persisted profile)
	// and a CLI "profile select && up" both surface here. Fired AFTER
	// all SetHidden/SetEnabled writes on the static menu items above so
	// loadProfiles' SetMenu rebuild (which clearMenu+processMenu the
	// entire NSMenu and re-assigns item.impl) cannot race those
	// writes — the Wails 3 alpha menu API is not goroutine-safe and
	// reads item.disabled/item.hidden at NSMenuItem construction time.
	go t.loadProfiles()
}

// applyStatusIndicator sets the small coloured dot shown on the status
// menu entry. The dot mirrors the tray icon's state through a fixed
// palette: green for Connected, yellow for Connecting, blue for the
// login states, red for hard errors, grey for the idle/disconnected
// pair and a darker grey when the daemon socket is unreachable.
//
// Wails v3 alpha's setMenuItemBitmap calls NSMenuItem.setImage from
// whichever thread invoked SetBitmap — unlike setMenuItemLabel/Disabled/
// Hidden/Checked which dispatch_sync onto the main queue. The off-thread
// AppKit call leaves the visible dot stale until the next time the menu
// is reopened (close+reopen workaround). Rebuilding via tray.SetMenu
// reruns processMenu inside InvokeSync, so the bitmap is applied to a
// fresh NSMenuItem on the main thread and macOS picks it up.
func (t *Tray) applyStatusIndicator(status string) {
	if t.statusItem == nil {
		return
	}
	t.statusItem.SetBitmap(statusIndicatorBitmap(status))
	if t.menu != nil {
		t.tray.SetMenu(t.menu)
	}
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
