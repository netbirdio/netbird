//go:build !android && !ios && !freebsd && !js

package main

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
	"github.com/wailsapp/wails/v3/pkg/services/notifications"

	nbstatus "github.com/netbirdio/netbird/client/status"
	"github.com/netbirdio/netbird/client/ui/authsession"
	"github.com/netbirdio/netbird/client/ui/i18n"
	"github.com/netbirdio/netbird/client/ui/services"
	"github.com/netbirdio/netbird/version"
)

// Translation keys for every user-facing string the tray paints. The text
// itself lives in frontend/src/i18n/locales/<lang>/common.json — both the
// tray and the React UI read from there so a single bundle drives the
// whole product. Keys are referenced by the Tray.tr helper.

// Non-translated identifiers. Notification IDs coalesce duplicate toasts
// (the OS uses them as dedup keys); statusError is a tray-only sentinel
// distinguishing the error-icon state from real daemon status strings;
// URLs are baked-in product links.
const (
	notifyIDUpdatePrefix   = "netbird-update-"
	notifyIDEvent          = "netbird-event-"
	notifyIDTrayError      = "netbird-tray-error"
	notifyIDSessionExpired = "netbird-session-expired"
	notifyIDSessionWarning = "netbird-session-warning"

	// notifyCategorySessionWarning groups the "Extend now" / "Dismiss"
	// actions on the T-10min OS notification. Registered once at tray
	// construction with the Wails notifications service; subsequent
	// SendNotificationWithActions calls reference it by ID.
	notifyCategorySessionWarning = "netbird-session-warning"
	notifyActionExtendNow        = "extend-now"
	notifyActionDismiss          = "dismiss"

	statusError = "Error"

	urlGitHubRepo     = "https://github.com/netbirdio/netbird"
	urlGitHubReleases = "https://github.com/netbirdio/netbird/releases/latest"

	// finalWarningCountdownSeconds is the countdown shown in the auto-opened
	// SessionAboutToExpire dialog. Mirrors sessionwatch.FinalWarningLead
	// (2 minutes); the values stay in sync by hand because the lead is fixed
	// for the initial rollout.
	finalWarningCountdownSeconds = 120
)


// Tray builds and updates the systray menu. It mirrors the layout of the Fyne
// systray 1:1 and routes clicks back to the gRPC services. Dynamic state
// (status icon, exit-node submenu) is driven by the netbird:status event.
// TrayServices bundles the daemon-RPC and notification services the tray
// menu needs. Grouped into a single struct so NewTray stays under the
// linter's parameter-count threshold and so adding another service later
// is a one-line struct change instead of a NewTray signature break.
type TrayServices struct {
	Connection      *services.Connection
	Settings        *services.Settings
	Profiles        *services.Profiles
	Peers           *services.Peers
	Notifier        *notifications.NotificationService
	Update          *services.Update
	ProfileSwitcher *services.ProfileSwitcher
	WindowManager   *services.WindowManager
	// Session drives the SSO session-extend flow invoked from the
	// "Extend now" action on the T-10min OS notification, plus the
	// Dismiss hand-off that suppresses the T-2 fallback dialog. Bound to
	// the authsession package directly because the Wails wrapper in
	// services only re-exposes the React-facing subset.
	Session *authsession.Session
	// Localizer is the tray's bridge to translations. Constructed in main
	// from i18n.Bundle + preferences.Store; the Wails-bound facades
	// (services.I18n, services.Preferences) are registered separately for
	// React and are not needed here.
	Localizer *Localizer
}

type Tray struct {
	app    *application.App
	tray   *application.SystemTray
	window *application.WebviewWindow
	svc    TrayServices
	// loc owns the active language plus the preference subscription. The
	// tray talks to it for every translated label (t.loc.T(...)) and
	// registers a callback in NewTray that re-renders the menu on a
	// language switch.
	loc *Localizer

	menu       *application.Menu
	statusItem *application.MenuItem
	// sessionExpiresItem displays the SSO session deadline as a humanised
	// remaining-time label ("Session: 47m"). Hidden when no deadline is
	// tracked (non-SSO peer or login-expiration disabled on the account).
	// Refreshed by applyStatus on every Status push and by a 1-minute
	// ticker between pushes so the countdown moves naturally.
	sessionExpiresItem *application.MenuItem
	upItem             *application.MenuItem
	downItem           *application.MenuItem
	exitNodeItem       *application.MenuItem
	networksItem       *application.MenuItem
	profileSubmenu     *application.Menu
	profileSubmenuItem *application.MenuItem
	profileEmailItem   *application.MenuItem
	settingsItem       *application.MenuItem
	debugItem          *application.MenuItem
	daemonVersionItem  *application.MenuItem

	updater *trayUpdater

	mu                   sync.Mutex
	connected            bool
	exitNodes            []string
	lastStatus           string
	lastDaemonVersion    string
	notificationsEnabled bool
	activeProfile        string
	activeUsername       string
	switchCancel         context.CancelFunc
	// sessionExpiresAt is the most recent deadline observed on a Status
	// snapshot. Used to skip a no-op label rewrite when the daemon repeats
	// the same value across rapid pushes. Guarded by mu.
	sessionExpiresAt time.Time
	// pendingConnectLogin is set when handleConnect kicks off an Up on an
	// idle daemon. The daemon will flip to NeedsLogin if the peer is
	// SSO-tracked and has no cached token; applyStatus consumes this flag
	// on that transition to automatically open the browser-login flow,
	// saving the user a second Connect click. Guarded by mu.
	pendingConnectLogin bool

	// profileLoadMu serializes loadProfiles so the daemon-status-driven
	// refresh in applyStatus cannot race with the ApplicationStarted seed
	// or the post-switchProfile reload — both manipulate profileSubmenu and
	// SetMenu, which the Wails menu API is not safe against concurrent
	// callers.
	profileLoadMu sync.Mutex
}

func NewTray(app *application.App, window *application.WebviewWindow, svc TrayServices) *Tray {
	t := &Tray{
		app:                  app,
		window:               window,
		svc:                  svc,
		notificationsEnabled: true,
		// Localizer is constructed by main from the i18n.Bundle and
		// preferences.Store so the first menu render below is already in
		// the right locale — no English flash followed by a re-paint.
		loc: svc.Localizer,
	}
	t.updater = newTrayUpdater(app, window, svc.Update, svc.Notifier, t.loc, func() { t.applyIcon() })
	t.tray = app.SystemTray.New()
	t.applyIcon()
	t.tray.SetTooltip(t.loc.T("tray.tooltip"))
	t.menu = t.buildMenu()
	t.tray.SetMenu(t.menu)
	// Left-click on the tray icon opens the menu on every platform. The
	// window is reached through the explicit "Open NetBird" entry. This
	// matches macOS NSStatusItem convention (click → menu), the Linux
	// StatusNotifierItem spec, and the legacy Fyne client. On Linux,
	// AttachWindow plus Wails3's applySmartDefaults would also pop the
	// window alongside the menu on environments like GNOME Shell with the
	// AppIndicator extension, so we intentionally skip both AttachWindow
	// and OnClick here. Right-click still opens the menu through Wails'
	// default rightClickHandler fallback.

	app.Event.On(services.EventStatus, t.onStatusEvent)
	app.Event.On(services.EventSystem, t.onSystemEvent)
	// Refresh the Profiles submenu when ProfileSwitcher fires the change.
	// applyStatus already reloads on status-text transitions, but a
	// switch on an idle daemon doesn't drive one — without this hook,
	// a React-initiated switch leaves the tray's submenu and active-
	// profile label stale.
	app.Event.On(services.EventProfileChanged, func(*application.CustomEvent) {
		go t.loadProfiles()
	})
	// Defer the first profile load until the macOS/GTK/Win32 menu impl is
	// live — Menu.Update() short-circuits while app.running is false, and
	// AppKit's main queue isn't ready earlier either (see d23ef34 InvokeSync
	// nil-deref).
	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		go t.loadProfiles()
		// Notification-category registration must run after the Wails
		// notifications service Startup has populated wn.appName /
		// registry path on Windows; before app.Run() the category lookup
		// in SendNotificationWithActions silently falls back to a
		// gomb-nélküli notification (the Windows impl logs "Category not
		// found"). The macOS/Linux impls don't strictly require this
		// ordering, but running here is harmless for them.
		t.registerSessionWarningCategory()
	})

	// Localizer fires this callback after it has already swapped its own
	// cached language, so every t.loc.T(...) lookup inside applyLanguage
	// runs against the new locale.
	t.loc.Watch(func(i18n.LanguageCode) { t.applyLanguage() })

	go t.loadConfig()
	return t
}

// applyLanguage re-renders every translated surface using the Localizer's
// current language. Wails dispatches menu/tray APIs onto the platform's
// UI thread internally, so calling them from the Localizer's background
// goroutine is safe; profileLoadMu prevents loadProfiles from racing the
// rebuild.
func (t *Tray) applyLanguage() {
	t.tray.SetTooltip(t.loc.T("tray.tooltip"))
	t.menu = t.buildMenu()
	t.tray.SetMenu(t.menu)
	t.reapplyMenuState()
}

// reapplyMenuState walks cached state and re-applies the visibility,
// enablement and label mutations that applyStatus would have performed
// since the last menu rebuild. Required after buildMenu because that
// constructor returns items in their default (disconnected) shape. The
// update menu item is re-applied by trayUpdater.applyLanguage.
func (t *Tray) reapplyMenuState() {
	t.mu.Lock()
	connected := t.connected
	lastStatus := t.lastStatus
	daemonVersion := t.lastDaemonVersion
	exitNodes := append([]string(nil), t.exitNodes...)
	sessionDeadline := t.sessionExpiresAt
	t.mu.Unlock()

	daemonUnavailable := strings.EqualFold(lastStatus, services.StatusDaemonUnavailable)
	connecting := strings.EqualFold(lastStatus, services.StatusConnecting)

	if t.statusItem != nil && lastStatus != "" {
		t.statusItem.SetLabel(t.loc.StatusLabel(lastStatus))
		t.statusItem.SetEnabled(statusRowEnabled())
		t.applyStatusIndicator(lastStatus)
	}
	if t.sessionExpiresItem != nil {
		if sessionDeadline.IsZero() {
			t.sessionExpiresItem.SetHidden(true)
		} else {
			remaining := nbstatus.FormatRemainingDuration(time.Until(sessionDeadline))
			t.sessionExpiresItem.SetLabel(t.loc.T("tray.session.expiresIn", "remaining", remaining))
			t.sessionExpiresItem.SetHidden(false)
		}
	}
	if t.upItem != nil {
		t.upItem.SetHidden(connected || connecting || daemonUnavailable)
		t.upItem.SetEnabled(!connected && !connecting && !daemonUnavailable)
	}
	if t.downItem != nil {
		t.downItem.SetHidden(!connected && !connecting)
		t.downItem.SetEnabled(connected || connecting)
	}
	if t.exitNodeItem != nil {
		t.exitNodeItem.SetEnabled(connected)
	}
	if t.networksItem != nil {
		t.networksItem.SetEnabled(connected)
	}
	if t.settingsItem != nil {
		t.settingsItem.SetEnabled(!daemonUnavailable)
	}
	if t.debugItem != nil {
		t.debugItem.SetEnabled(!daemonUnavailable)
	}
	if t.profileSubmenuItem != nil {
		t.profileSubmenuItem.SetEnabled(!daemonUnavailable)
	}
	if daemonVersion != "" && t.daemonVersionItem != nil {
		t.daemonVersionItem.SetLabel(t.loc.T("tray.menu.daemonVersion", "version", daemonVersion))
	}
	if t.updater != nil {
		t.updater.applyLanguage()
	}
	if len(exitNodes) > 0 {
		t.rebuildExitNodes(exitNodes)
	}
	go t.loadProfiles()
}

// ShowWindow brings the main window forward — used by SIGUSR1 / Windows event.
// Show() alone is not enough on macOS: makeKeyAndOrderFront skips app
// activation, so a tray-style app's window pops up behind the currently
// active app. Focus() additionally calls activateIgnoringOtherApps:YES on
// macOS and SetForegroundWindow on Windows.
func (t *Tray) ShowWindow() {
	// While an SSO flow is in progress the BrowserLogin popup is the focal
	// window — the main window was hidden by WindowManager so the user
	// stays on the sign-in surface. Tray "Open" / SIGUSR1 / dock-reopen
	// should bring that window forward, not resurrect the main one mid-flow.
	if w := t.svc.WindowManager.BrowserLoginWindow(); w != nil {
		w.Show()
		w.Focus()
		return
	}
	if t.window == nil {
		return
	}
	t.window.Show()
	t.window.Focus()
}

func (t *Tray) buildMenu() *application.Menu {
	menu := application.NewMenu()

	// statusItem shows the daemon's current status. Informational row
	// with no OnClick handler — clicks are no-ops. Whether the row is
	// kept enabled is platform-dependent (see statusRowEnabled): on
	// Windows the disabled-state mask would desaturate the coloured
	// status dot painted into the check-mark slot, so the row stays
	// enabled there; macOS/Linux disable it so the greyed-out label
	// signals that it is not clickable. The Connect entry below drives
	// every actionable transition, including the SSO re-auth flow for
	// NeedsLogin/SessionExpired (the daemon's Up RPC returns
	// NeedsSSOLogin when applicable).
	t.statusItem = menu.Add(t.loc.T("tray.status.disconnected")).
		SetEnabled(statusRowEnabled()).
		SetBitmap(iconMenuDotIdle)

	// sessionExpiresItem sits directly below the status row so the
	// remaining-time label reads as a sub-line of "Connected" etc. Hidden
	// until applyStatus sees a non-zero SessionExpiresAt on the daemon
	// Status snapshot — peers without SSO tracking or with login expiry
	// disabled never reveal this row.
	t.sessionExpiresItem = menu.Add("").SetEnabled(false)
	t.sessionExpiresItem.SetHidden(true)

	menu.AddSeparator()
	// The tray icon's left-click handler is intentionally unbound (see
	// NewTray for the rationale), so expose the window through an explicit
	// menu entry on every platform.
	menu.Add(t.loc.T("tray.menu.open")).OnClick(func(*application.Context) { t.ShowWindow() })
	menu.AddSeparator()
	// Profiles submenu is populated asynchronously once the application
	// has started — Menu.Update() is a no-op before app.running is true,
	// so the initial fill is gated on the ApplicationStarted hook.
	profilesLabel := t.loc.T("tray.menu.profiles")
	t.profileSubmenu = menu.AddSubmenu(profilesLabel)
	// profileSubmenuItem is the parent MenuItem whose label is the active
	// profile name. AddSubmenu returns the child *Menu, so we retrieve the
	// parent *MenuItem via FindByLabel immediately after insertion.
	t.profileSubmenuItem = menu.FindByLabel(profilesLabel)
	// profileEmailItem shows the account email of the active profile directly
	// in the main menu, below the Profiles submenu — matching the behaviour of
	// the legacy Fyne/systray UI. It is hidden until loadProfiles resolves a
	// non-empty email for the active profile.
	t.profileEmailItem = menu.Add("").SetEnabled(false)
	t.profileEmailItem.SetHidden(true)
	menu.AddSeparator()
	// Only the action that applies to the current state is visible: Connect
	// when disconnected, Disconnect when connected. applyStatus swaps them on
	// each daemon status change.
	t.upItem = menu.Add(t.loc.T("tray.menu.connect")).OnClick(func(*application.Context) { t.handleConnect() })
	t.downItem = menu.Add(t.loc.T("tray.menu.disconnect")).OnClick(func(*application.Context) { t.handleDisconnect() })
	t.downItem.SetHidden(true)

	menu.AddSeparator()

	t.exitNodeItem = menu.Add(t.loc.T("tray.menu.exitNode")).SetEnabled(false)
	t.networksItem = menu.Add(t.loc.T("tray.menu.networks")).OnClick(func(*application.Context) { t.openRoute("/networks") })

	menu.AddSeparator()

	// Settings, runtime toggles (SSH, Quantum-Resistance, lazy connection,
	// block-inbound, auto-connect, notifications) and profile switching
	// all live in the in-window Settings page now. The tray menu only
	// surfaces the day-to-day actions.
	t.settingsItem = menu.Add(t.loc.T("tray.menu.settings")).OnClick(func(*application.Context) { t.svc.WindowManager.OpenSettings("") })
	t.debugItem = menu.Add(t.loc.T("tray.menu.debugBundle")).OnClick(func(*application.Context) { t.openRoute("/debug") })

	menu.AddSeparator()

	aboutLabel := t.loc.T("tray.menu.about")
	about := menu.AddSubmenu(aboutLabel)
	if aboutItem := menu.FindByLabel(aboutLabel); aboutItem != nil {
		aboutItem.SetBitmap(iconMenuNetbird)
	}
	about.Add(t.loc.T("tray.menu.github")).OnClick(func(*application.Context) {
		_ = t.app.Browser.OpenURL(urlGitHubRepo)
	})
	about.Add(t.loc.T("tray.menu.documentation")).SetEnabled(false)
	// Disabled informational entries: the GUI version is baked in at
	// build time via -ldflags, the daemon version comes from the first
	// Status snapshot and is updated in applyStatus.
	about.Add(t.loc.T("tray.menu.guiVersion", "version", version.NetbirdVersion())).SetEnabled(false)
	t.daemonVersionItem = about.Add(t.loc.T("tray.menu.daemonVersion", "version", t.loc.T("tray.menu.versionUnknown"))).SetEnabled(false)
	// Update menu item is hidden until the daemon reports a new version
	// (EventUpdateState with Available=true). trayUpdater rewrites the
	// label between tray.menu.downloadLatest (opt-in) and
	// tray.menu.installVersion (enforced) and drives the click.
	updateItem := about.Add(t.loc.T("tray.menu.downloadLatest")).
		OnClick(func(*application.Context) { t.updater.handleClick() })
	updateItem.SetHidden(true)
	t.updater.attach(updateItem)

	menu.AddSeparator()
	menu.Add(t.loc.T("tray.menu.quit")).OnClick(func(*application.Context) { t.app.Quit() })

	return menu
}

func (t *Tray) openRoute(route string) {
	if t.window == nil {
		return
	}
	t.window.Show()
	t.window.Focus()
	t.window.SetURL("/#" + route)
}

func (t *Tray) handleConnect() {
	// NeedsLogin/SessionExpired/LoginFailed mean the daemon won't honor a
	// plain Up RPC ("up already in progress: current status NeedsLogin") —
	// it needs the Login → WaitSSOLogin → Up sequence instead. Hand off
	// to the React-side startLogin() (which owns the browser-login window
	// and SSO orchestration) by showing the main window and emitting
	// EventTriggerLogin. The frontend subscribes in
	// layouts/ConnectionStatusSwitch.tsx.
	t.mu.Lock()
	needsLogin := strings.EqualFold(t.lastStatus, services.StatusNeedsLogin) ||
		strings.EqualFold(t.lastStatus, services.StatusSessionExpired) ||
		strings.EqualFold(t.lastStatus, services.StatusLoginFailed)
	t.mu.Unlock()
	if needsLogin {
		t.ShowWindow()
		t.app.Event.Emit(services.EventTriggerLogin)
		return
	}
	t.upItem.SetEnabled(false)
	// Arm the SSO auto-handoff: Up() is async and the daemon may flip to
	// NeedsLogin once it detects an SSO peer with no cached token. The
	// flag is consumed by applyStatus on that transition, which then
	// triggers the browser-login flow without the user having to click
	// Connect a second time. Cleared on any terminal state (Connected /
	// Idle / LoginFailed / DaemonUnavailable / SessionExpired) so a stale
	// flag can't hijack a future status push.
	t.mu.Lock()
	t.pendingConnectLogin = true
	t.mu.Unlock()
	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := t.svc.Connection.Up(ctx, services.UpParams{}); err != nil {
			log.Errorf("connect: %v", err)
			t.notifyError(t.loc.T("notify.error.connect"))
			t.mu.Lock()
			t.pendingConnectLogin = false
			t.mu.Unlock()
			t.upItem.SetEnabled(true)
		}
	}()
}

// handleDisconnect aborts any in-flight profile switch before sending
// Down — otherwise the switcher's queued Up would re-establish the
// connection right after the Disconnect, making the click look like a
// no-op. Also clears Peers' optimistic-Connecting guard so the daemon's
// Idle push (and any subsequent updates) paint through immediately
// instead of being swallowed by the profile-switch suppression filter.
func (t *Tray) handleDisconnect() {
	t.downItem.SetEnabled(false)
	t.mu.Lock()
	if t.switchCancel != nil {
		t.switchCancel()
		t.switchCancel = nil
	}
	t.mu.Unlock()
	t.svc.Peers.CancelProfileSwitch()
	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := t.svc.Connection.Down(ctx); err != nil {
			log.Errorf("disconnect: %v", err)
			t.notifyError(t.loc.T("notify.error.disconnect"))
			t.downItem.SetEnabled(true)
		}
	}()
}

func (t *Tray) onStatusEvent(ev *application.CustomEvent) {
	st, ok := ev.Data.(services.Status)
	if !ok {
		return
	}
	t.applyStatus(st)
}

// onSystemEvent fires an OS notification for daemon SystemEvents that carry
// a user-facing message, mirroring the legacy event.Manager behaviour: gated
// by the user's "Notifications" toggle, with CRITICAL events bypassing the
// gate. Update-related events are skipped here because trayUpdater produces
// its own richer notification when EventUpdateState fires.
func (t *Tray) onSystemEvent(ev *application.CustomEvent) {
	se, ok := ev.Data.(services.SystemEvent)
	if !ok {
		return
	}
	// Session-warning events carry no UserMessage — the tray builds the
	// localised notification body locally from metadata. Every other
	// event needs a non-empty UserMessage to show anything meaningful.
	isSessionWarning := se.Metadata[authsession.MetaWarning] == "true"
	if !isSessionWarning && se.UserMessage == "" {
		return
	}
	if _, isUpdate := se.Metadata["new_version_available"]; isUpdate {
		return
	}
	if _, isProgress := se.Metadata["progress_window"]; isProgress {
		return
	}
	// Management pairs ::/0 with 0.0.0.0/0 for exit-node default routes;
	// the v4 partner already drives the user-facing toast, so the v6 one
	// is suppressed to avoid a duplicate notification.
	if se.Category == "network" && se.Metadata["network"] == "::/0" {
		return
	}

	critical := se.Severity == "critical"
	t.mu.Lock()
	enabled := t.notificationsEnabled
	t.mu.Unlock()
	if !enabled && !critical {
		return
	}

	// Session-warning events come in two flavours; detect via the stable
	// metadata flags rather than category/severity so a future reword on
	// the daemon side still routes here.
	//   - T-WarningLead (MetaSessionWarning + no MetaSessionFinal) →
	//     interactive "Extend now / Dismiss" OS notification. Title and
	//     body are built locally from i18n + metadata so the text follows
	//     the active UI language regardless of what the daemon (which has
	//     no locale context) writes into UserMessage.
	//   - T-FinalWarningLead (MetaSessionFinal=true) → auto-open the
	//     SessionAboutToExpire dialog. No OS notification here; the
	//     dialog is the last-chance reminder, doubling up would be noise.
	if se.Metadata != nil && se.Metadata[authsession.MetaWarning] == "true" {
		if se.Metadata[authsession.MetaFinal] == "true" {
			t.openSessionAboutToExpire()
			return
		}
		t.notifySessionWarning(
			t.loc.T("notify.sessionWarning.title"),
			t.buildSessionWarningBody(se.Metadata),
		)
		return
	}

	body := se.UserMessage
	if id := se.Metadata["id"]; id != "" {
		body += fmt.Sprintf(" ID: %s", id)
	}
	t.notify(eventTitle(se), body, notifyIDEvent+se.ID)
}

// applyStatus updates the tray icon, status label, exit-node submenu, and
// connect/disconnect enablement based on the latest daemon snapshot.
// Skips the icon refresh when none of the icon-relevant inputs
// (connected, hasUpdate, status label) changed — the daemon emits
// rapid SubscribeStatus bursts during health probes that would
// otherwise spam Shell_NotifyIcon and the log.
//
// Profile-switch suppression lives one layer up in services/peers.go
// (Peers.BeginProfileSwitch / shouldSuppress) so the optimistic
// Connecting paint and the suppressed Idle/Connected events are shared
// with the React Status page rather than being a tray-only behaviour.
func (t *Tray) applyStatus(st services.Status) {
	t.mu.Lock()
	connected := strings.EqualFold(st.Status, services.StatusConnected)
	iconChanged := connected != t.connected || st.Status != t.lastStatus
	// Detect the transition into SessionExpired: the daemon emits the
	// state on every Status snapshot for as long as the session stays
	// expired, so without this guard we would re-fire the notification
	// on every push. Mirrors the legacy Fyne client's sendNotification
	// flag in onSessionExpire.
	sessionExpiredEnter := strings.EqualFold(st.Status, services.StatusSessionExpired) &&
		!strings.EqualFold(t.lastStatus, services.StatusSessionExpired)

	// Consume the SSO auto-handoff flag armed by handleConnect. Trigger
	// the browser-login flow on a Connect → NeedsLogin transition so the
	// user doesn't need to click Connect a second time. Clear it on any
	// other terminal state — including Connecting bursts that resolve to
	// Connected / Idle / LoginFailed / DaemonUnavailable — so a stale
	// flag can't fire weeks later when the daemon happens to flip.
	triggerLogin := false
	if t.pendingConnectLogin {
		switch {
		case strings.EqualFold(st.Status, services.StatusNeedsLogin):
			triggerLogin = true
			t.pendingConnectLogin = false
		case strings.EqualFold(st.Status, services.StatusConnected),
			strings.EqualFold(st.Status, services.StatusIdle),
			strings.EqualFold(st.Status, services.StatusLoginFailed),
			strings.EqualFold(st.Status, services.StatusSessionExpired),
			strings.EqualFold(st.Status, services.StatusDaemonUnavailable):
			t.pendingConnectLogin = false
		}
	}

	daemonVersionChanged := st.DaemonVersion != "" && st.DaemonVersion != t.lastDaemonVersion
	t.connected = connected
	t.lastStatus = st.Status
	if daemonVersionChanged {
		t.lastDaemonVersion = st.DaemonVersion
	}

	exitNodes := exitNodesFromStatus(st)
	exitNodesChanged := !equalStrings(exitNodes, t.exitNodes)
	t.exitNodes = exitNodes
	t.mu.Unlock()

	if triggerLogin {
		t.ShowWindow()
		t.app.Event.Emit(services.EventTriggerLogin)
	}

	if iconChanged {
		t.applyIcon()
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
		// Exit Node and Resources surface tunnel-routed state, so only
		// expose them while the tunnel is up. Settings/Debug-Bundle just
		// need the daemon socket reachable.
		if t.exitNodeItem != nil {
			t.exitNodeItem.SetEnabled(connected)
		}
		if t.networksItem != nil {
			t.networksItem.SetEnabled(connected)
		}
		if t.settingsItem != nil {
			t.settingsItem.SetEnabled(!daemonUnavailable)
		}
		if t.debugItem != nil {
			t.debugItem.SetEnabled(!daemonUnavailable)
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
	if exitNodesChanged {
		t.rebuildExitNodes(exitNodes)
	}
	if daemonVersionChanged && t.daemonVersionItem != nil {
		t.daemonVersionItem.SetLabel(t.loc.T("tray.menu.daemonVersion", "version", st.DaemonVersion))
	}
	if sessionExpiredEnter {
		t.handleSessionExpired()
	}

	t.applySessionExpiry(st.SessionExpiresAt, connected)
}

// handleSessionExpired surfaces the SSO re-authentication path when the
// daemon reports StatusSessionExpired. Posts a single OS notification
// (the applyStatus guard ensures it fires only on the transition, not
// on every status snapshot) and brings the main window forward so the
// frontend's /login route can drive the renewed SSO flow. Mirrors the
// Fyne client's onSessionExpire, which used a runSelfCommand to spawn
// the login-url helper; here the window is already in-process.
func (t *Tray) handleSessionExpired() {
	t.notify(t.loc.T("notify.sessionExpired.title"), t.loc.T("notify.sessionExpired.body"), notifyIDSessionExpired)
	if t.window != nil {
		t.window.SetURL("/#/login")
		t.window.Show()
		t.window.Focus()
	}
}

func (t *Tray) rebuildExitNodes(nodes []string) {
	if t.exitNodeItem == nil || len(nodes) == 0 {
		return
	}
	sub := application.NewMenu()
	for _, fqdn := range nodes {
		sub.AddCheckbox(fqdn, false)
	}
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
		return iconMenuDotLogin
	case strings.EqualFold(status, services.StatusLoginFailed),
		strings.EqualFold(status, statusError):
		return iconMenuDotError
	case strings.EqualFold(status, services.StatusDaemonUnavailable):
		return iconMenuDotOffline
	default:
		return iconMenuDotIdle
	}
}

func (t *Tray) applyIcon() {
	t.mu.Lock()
	connected := t.connected
	statusLabel := t.lastStatus
	t.mu.Unlock()
	hasUpdate := false
	if t.updater != nil {
		hasUpdate = t.updater.hasUpdate()
	}

	log.Infof("tray applyIcon: connected=%v hasUpdate=%v status=%q goos=%s",
		connected, hasUpdate, statusLabel, runtime.GOOS)

	icon, dark := t.iconForState()
	if runtime.GOOS == "darwin" {
		t.tray.SetTemplateIcon(icon)
		return
	}
	t.tray.SetIcon(icon)
	if dark != nil {
		t.tray.SetDarkModeIcon(dark)
	}
}

func (t *Tray) iconForState() (icon, dark []byte) {
	t.mu.Lock()
	connected := t.connected
	statusLabel := t.lastStatus
	t.mu.Unlock()
	hasUpdate := false
	if t.updater != nil {
		hasUpdate = t.updater.hasUpdate()
	}

	connecting := strings.EqualFold(statusLabel, services.StatusConnecting)
	errored := strings.EqualFold(statusLabel, statusError) ||
		strings.EqualFold(statusLabel, services.StatusDaemonUnavailable)
	needsLogin := strings.EqualFold(statusLabel, services.StatusNeedsLogin) ||
		strings.EqualFold(statusLabel, services.StatusSessionExpired) ||
		strings.EqualFold(statusLabel, services.StatusLoginFailed)

	if runtime.GOOS == "darwin" {
		switch {
		case connecting:
			return iconConnectingMacOS, nil
		case errored:
			return iconErrorMacOS, nil
		case needsLogin:
			return iconNeedsLoginMacOS, nil
		case connected && hasUpdate:
			return iconUpdateConnectedMacOS, nil
		case connected:
			return iconConnectedMacOS, nil
		case hasUpdate:
			return iconUpdateDisconnectedMacOS, nil
		default:
			return iconDisconnectedMacOS, nil
		}
	}

	switch {
	case connecting:
		return iconConnecting, nil
	case errored:
		return iconError, nil
	case needsLogin:
		return iconNeedsLogin, nil
	case connected && hasUpdate:
		return iconUpdateConnected, nil
	case connected:
		return iconConnected, iconConnectedDark
	case hasUpdate:
		return iconUpdateDisconnected, nil
	default:
		return iconDisconnected, nil
	}
}

// loadConfig seeds the in-process notifications gate from the daemon's
// stored config and caches the active-profile identity for any future
// SetConfig calls. Called once at startup from a goroutine so a slow or
// unreachable daemon does not block menu construction.
//
// The Settings page in the main window is the source of truth for every
// other knob (SSH, auto-connect, Rosenpass, lazy connections, block-inbound,
// notifications); we only mirror the notifications flag because the tray
// itself uses it to gate OS toasts in onSystemEvent.
func (t *Tray) loadConfig() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	active, err := t.svc.Profiles.GetActive(ctx)
	if err != nil {
		log.Debugf("get active profile: %v", err)
		return
	}
	cfg, err := t.svc.Settings.GetConfig(ctx, services.ConfigParams(active))
	if err != nil {
		log.Debugf("get config: %v", err)
		return
	}

	t.mu.Lock()
	t.activeProfile = active.ProfileName
	t.activeUsername = active.Username
	t.notificationsEnabled = !cfg.DisableNotifications
	t.mu.Unlock()
}

// loadProfiles refreshes the Profiles submenu from the daemon. Each
// entry is a checkbox showing the active profile and switches on click.
// Called on ApplicationStarted, after a successful switchProfile, and
// from applyStatus whenever the daemon's status text changes — the
// last case catches profile flips driven by another channel (CLI
// "netbird profile select", autoconnect picking the persisted profile
// after the UI's first ListProfiles, etc.) since the daemon does not
// emit a dedicated active-profile event.
func (t *Tray) loadProfiles() {
	if t.profileSubmenu == nil {
		return
	}
	t.profileLoadMu.Lock()
	defer t.profileLoadMu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	username, err := t.svc.Profiles.Username()
	if err != nil {
		log.Debugf("get current user: %v", err)
		return
	}
	profiles, err := t.svc.Profiles.List(ctx, username)
	if err != nil {
		log.Debugf("list profiles: %v", err)
		return
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Name < profiles[j].Name })

	log.Infof("tray loadProfiles: received %d profile(s) for user %q", len(profiles), username)
	t.profileSubmenu.Clear()
	var activeName, activeEmail string
	for _, p := range profiles {
		name := p.Name
		active := p.IsActive
		log.Infof("tray loadProfiles: profile=%q active=%v", name, active)
		// Use Add instead of AddCheckbox: Wails auto-toggles a checkbox's
		// checked state on click (before the OnClick handler fires), so with
		// AddCheckbox both the old and the new profile would briefly show as
		// checked while the switchProfile goroutine is running. A plain item
		// with a "✓ " prefix avoids the race entirely.
		label := name
		if active {
			label = "✓ " + name
		}
		item := t.profileSubmenu.Add(label)
		item.OnClick(func(*application.Context) {
			log.Infof("tray profile click: profile=%q wasActive=%v", name, active)
			if active {
				return
			}
			t.switchProfile(name)
		})
		if active {
			activeName = name
			activeEmail = p.Email
		}
	}
	if t.profileSubmenuItem != nil && activeName != "" {
		t.profileSubmenuItem.SetLabel(activeName)
	}
	if t.profileEmailItem != nil {
		if activeEmail != "" {
			t.profileEmailItem.SetLabel(fmt.Sprintf("(%s)", activeEmail))
			t.profileEmailItem.SetHidden(false)
		} else {
			t.profileEmailItem.SetHidden(true)
		}
	}
	// Wails v3 alpha's submenu.Update() builds a fresh, detached NSMenu on
	// darwin that never replaces the empty NSMenu attached to the parent
	// menu item at initial setup — so the visible Profiles menu stays
	// frozen on the snapshot taken when the tray was registered. Re-running
	// SetMenu on the top-level rebuilds the entire NSMenu tree against the
	// cached pointer and is the only path that propagates submenu changes.
	if t.menu != nil {
		t.tray.SetMenu(t.menu)
	} else {
		t.profileSubmenu.Update()
	}
}

// switchProfile cancels any in-flight profile switch, then starts a new one.
// Cancelling the previous context aborts its in-flight gRPC calls (Down/Up)
// so rapid clicks always converge to the last selected profile.
//
// The optimistic Connecting paint (and suppression of the transient
// Idle/stale Connected daemon events that follow Down) lives in
// services/peers.go — ProfileSwitcher calls Peers.BeginProfileSwitch
// when the previous status was Connected/Connecting, which emits a
// synthetic Connecting status to the event bus and starts filtering
// the daemon stream. That way both this tray and the React Status
// page see the same optimistic state without duplicating policy.
func (t *Tray) switchProfile(name string) {
	t.mu.Lock()
	if t.switchCancel != nil {
		t.switchCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.switchCancel = cancel
	t.mu.Unlock()

	go func() {
		username, err := t.svc.Profiles.Username()
		if err != nil {
			log.Errorf("tray switchProfile: get current user: %v", err)
			return
		}
		if err := t.svc.ProfileSwitcher.SwitchActive(ctx, services.ProfileRef{
			ProfileName: name,
			Username:    username,
		}); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Errorf("tray switchProfile: %v", err)
			t.notifyError(t.loc.T("notify.error.switchProfile", "profile", name))
			return
		}
		t.loadProfiles()
	}()
}

// applySessionExpiry refreshes the "Session: 47m" tray row from the latest
// Status snapshot's SessionExpiresAt. Only shown when the tunnel is up:
// in any other state (Idle after a Down, Connecting, NeedsLogin,
// SessionExpired, LoginFailed, DaemonUnavailable, or mid profile-switch)
// the deadline is meaningless and the row is hidden. The internal
// sessionExpiresAt cache is cleared in the same path so reapplyMenuState
// after a language switch doesn't resurrect a stale label.
//
// No per-minute ticker: between Status pushes the label may drift by a
// few minutes, which is fine for a tray-menu status row that the user
// opens on demand. The T-10min OS notification (driven by the daemon's
// sessionwatch) does the time-critical signalling.
func (t *Tray) applySessionExpiry(deadline *time.Time, connected bool) {
	var d time.Time
	if connected && deadline != nil {
		d = *deadline
	}

	t.mu.Lock()
	t.sessionExpiresAt = d
	t.mu.Unlock()

	if t.sessionExpiresItem == nil {
		return
	}
	if d.IsZero() {
		t.sessionExpiresItem.SetHidden(true)
		return
	}
	remaining := nbstatus.FormatRemainingDuration(time.Until(d))
	t.sessionExpiresItem.SetLabel(t.loc.T("tray.session.expiresIn", "remaining", remaining))
	t.sessionExpiresItem.SetHidden(false)
}

// notify wraps the Wails notification service with the tray's standard
// id-prefix scheme and swallows errors (notifications are best-effort).
func (t *Tray) notify(title, body, id string) {
	if t.svc.Notifier == nil {
		return
	}
	if err := t.svc.Notifier.SendNotification(notifications.NotificationOptions{
		ID:    id,
		Title: title,
		Body:  body,
	}); err != nil {
		log.Debugf("notify %q: %v", title, err)
	}
}

// registerSessionWarningCategory wires the OS notification category for the
// T-10min SSO expiry warning. The category carries two actions ("Extend now"
// and "Dismiss") and the global response handler so a click resolves back
// into runExtendSession. Idempotent — called once from NewTray; errors are
// logged and swallowed because the worst case is a plain text notification
// without buttons.
func (t *Tray) registerSessionWarningCategory() {
	if t.svc.Notifier == nil {
		return
	}
	if err := t.svc.Notifier.RegisterNotificationCategory(notifications.NotificationCategory{
		ID: notifyCategorySessionWarning,
		Actions: []notifications.NotificationAction{
			{ID: notifyActionExtendNow, Title: t.loc.T("notify.sessionWarning.extend")},
			{ID: notifyActionDismiss, Title: t.loc.T("notify.sessionWarning.dismiss")},
		},
	}); err != nil {
		log.Debugf("register session-warning notification category: %v", err)
	}
	t.svc.Notifier.OnNotificationResponse(func(result notifications.NotificationResult) {
		if result.Error != nil {
			log.Debugf("notification response error: %v", result.Error)
			return
		}
		if result.Response.CategoryID != notifyCategorySessionWarning {
			return
		}
		switch result.Response.ActionIdentifier {
		case notifyActionExtendNow, notifications.DefaultActionIdentifier:
			// DefaultActionIdentifier covers the body-click on platforms
			// that don't expose buttons separately (e.g. some minimal
			// Linux notification daemons fall back to a single click
			// area). Treat it as Extend so the user always has a path.
			go t.runExtendSession()
		case notifyActionDismiss:
			// Explicit user opt-out. Tell the daemon so the
			// T-FinalWarningLead fallback dialog stays closed for this
			// deadline; the regular watcher remains armed for the next
			// deadline value (e.g. after a successful extend elsewhere).
			go t.dismissSessionWarning()
		}
	})
}

// buildSessionWarningBody composes the localised body for the T-10min
// notification from the daemon's metadata. The daemon does not have a
// locale, so it ships a stable RFC3339 deadline ("session_expires_at")
// and integer lead time ("lead_minutes") in metadata; the tray turns
// them into a user-language sentence via the active i18n bundle.
//
// Falls back to a constant string when the metadata is missing or the
// timestamp fails to parse — the user still sees the warning, just
// without the remaining-time count.
func (t *Tray) buildSessionWarningBody(meta map[string]string) string {
	if meta == nil {
		return t.loc.T("notify.sessionWarning.bodyGeneric")
	}
	raw := meta[authsession.MetaExpiresAt]
	if raw == "" {
		return t.loc.T("notify.sessionWarning.bodyGeneric")
	}
	deadline, err := authsession.ParseExpiresAt(raw)
	if err != nil {
		return t.loc.T("notify.sessionWarning.bodyGeneric")
	}
	remaining := nbstatus.FormatRemainingDuration(time.Until(deadline))
	return t.loc.T("notify.sessionWarning.body", "remaining", remaining)
}

// notifySessionWarning sends the interactive T-10min OS notification. Falls
// back to the plain `notify` helper if the Wails service doesn't expose the
// with-actions variant (older platform impls, or a bare Notifier in tests).
func (t *Tray) notifySessionWarning(title, body string) {
	if t.svc.Notifier == nil {
		return
	}
	err := t.svc.Notifier.SendNotificationWithActions(notifications.NotificationOptions{
		ID:         notifyIDSessionWarning,
		Title:      title,
		Body:       body,
		CategoryID: notifyCategorySessionWarning,
	})
	if err != nil {
		log.Debugf("notify session-warning with actions: %v", err)
		// Fall back to a plain notification so the user at least gets
		// the warning text, even without buttons.
		t.notify(title, body, notifyIDSessionWarning)
	}
}

// runExtendSession drives the daemon's RequestExtendAuthSession +
// WaitExtendAuthSession pair when the user clicks "Extend now" on the
// session-warning notification. Mirrors `doExtendSession` in
// client/cmd/login.go but talks to the in-process Wails Session service
// instead of opening a daemon gRPC channel from a CLI process. The
// browser is opened via Connection.OpenURL (which honours $BROWSER on
// Unix). Errors surface as plain notifyError calls — there is no foreground
// UI flow here because the warning may fire while the main window is
// closed.
func (t *Tray) runExtendSession() {
	if t.svc.Session == nil || t.svc.Connection == nil {
		log.Debugf("session-warning: extend requested but services not wired")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	start, err := t.svc.Session.RequestExtend(ctx, services.ExtendStartParams{})
	if err != nil {
		log.Warnf("session-warning: RequestExtend failed: %v", err)
		t.notifyError(t.loc.T("notify.sessionWarning.failed"))
		return
	}

	uri := start.VerificationURIComplete
	if uri == "" {
		uri = start.VerificationURI
	}
	if uri != "" {
		if err := t.svc.Connection.OpenURL(uri); err != nil {
			log.Debugf("session-warning: opening verification URL: %v", err)
		}
	}

	if _, err := t.svc.Session.WaitExtend(ctx, services.ExtendWaitParams{
		DeviceCode: start.DeviceCode,
		UserCode:   start.UserCode,
	}); err != nil {
		log.Warnf("session-warning: WaitExtend failed: %v", err)
		t.notifyError(t.loc.T("notify.sessionWarning.failed"))
		return
	}
	t.notify(t.loc.T("notify.sessionWarning.successTitle"), t.loc.T("notify.sessionWarning.successBody"), notifyIDSessionWarning)
}

// dismissSessionWarning tells the daemon to silence the T-FinalWarningLead
// fallback dialog for the current deadline. Best-effort: a failure only
// means the dialog will still appear, so we log and move on.
func (t *Tray) dismissSessionWarning() {
	if t.svc.Session == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := t.svc.Session.DismissWarning(ctx); err != nil {
		log.Debugf("session-warning: DismissWarning failed: %v", err)
	}
}

// openSessionAboutToExpire fires the auto-opened fallback dialog at
// T-FinalWarningLead when the user did not dismiss the earlier T-10
// notification. Idempotent on the WindowManager side (a second call
// while the window is already open is a no-op).
func (t *Tray) openSessionAboutToExpire() {
	if t.svc.WindowManager == nil {
		return
	}
	t.svc.WindowManager.OpenSessionAboutToExpire(finalWarningCountdownSeconds)
}

// notifyError fires a generic "Error" notification for tray-driven action
// failures. Each tray click site already logs the underlying error; this
// adds the user-visible toast.
func (t *Tray) notifyError(message string) {
	t.notify(t.loc.T("notify.error.title"), message, notifyIDTrayError)
}

func exitNodesFromStatus(st services.Status) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, p := range st.Peers {
		if p.Fqdn == "" {
			continue
		}
		if _, ok := seen[p.Fqdn]; ok {
			continue
		}
		seen[p.Fqdn] = struct{}{}
		out = append(out, p.Fqdn)
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// eventTitle composes a notification title from a SystemEvent's severity and
// category — "Critical: DNS", "Warning: Authentication", etc. — matching the
// format the legacy Fyne event.Manager produced.
func eventTitle(e services.SystemEvent) string {
	prefix := titleCase(e.Severity)
	if prefix == "" {
		prefix = "Info"
	}
	category := titleCase(e.Category)
	if category == "" {
		category = "System"
	}
	return prefix + ": " + category
}

func titleCase(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}
