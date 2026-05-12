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

	"github.com/netbirdio/netbird/client/ui/services"
	"github.com/netbirdio/netbird/version"
)

// User-facing strings exposed in the tray, OS notifications and the
// browser-opened URLs. Centralised here so future copy edits and (one
// day) localisation have a single source of truth.
const (
	trayTooltip = "NetBird"

	// Top-level menu entries.
	menuStatusDisconnected      = "Disconnected"
	menuStatusDaemonUnavailable = "Not running"
	menuOpenNetBird             = "Open NetBird"
	menuConnect                 = "Connect"
	menuDisconnect              = "Disconnect"
	menuExitNode                = "Exit Node"
	menuNetworks                = "Resources"
	menuProfiles                = "Profiles"
	menuQuit                    = "Quit"

	// Settings + diagnostics. The settings page replaces the Fyne tray's
	// Settings submenu (per-toggle checkboxes for SSH, auto-connect,
	// Rosenpass, lazy connections, block-inbound, notifications); those
	// live in the in-window Settings page now.
	menuSettings          = "Settings"
	menuCreateDebugBundle = "Create Debug Bundle"

	// About submenu and update flow.
	menuAbout                 = "About"
	menuGitHub                = "GitHub"
	menuDocumentation         = "Documentation"
	menuDownloadLatestVersion = "Download latest version"
	// menuInstallVersionPrefix is rewritten with the target version when
	// the management server enforces the update.
	menuInstallVersionPrefix = "Install version "
	// menuGUIVersionFmt and menuDaemonVersionFmt drive the disabled
	// version-info entries under About. The daemon line is "—" until the
	// first Status snapshot reports the daemon's version.
	menuGUIVersionFmt    = "GUI: %s"
	menuDaemonVersionFmt = "Daemon: %s"
	menuVersionUnknown   = "—"

	// OS notifications.
	notifyUpdateTitle          = "NetBird update available"
	notifyUpdateBodyFmt        = "NetBird %s is available."
	notifyUpdateEnforcedSuffix = " Your administrator requires this update."
	notifyErrorTitle           = "Error"
	notifyErrorConnect         = "Failed to connect"
	notifyErrorDisconnect      = "Failed to disconnect"
	notifySessionExpiredTitle  = "NetBird session expired"
	notifySessionExpiredBody   = "Your NetBird session has expired. Please log in again."

	// Notification IDs (used to coalesce duplicate toasts).
	notifyIDUpdatePrefix   = "netbird-update-"
	notifyIDEvent          = "netbird-event-"
	notifyIDTrayError      = "netbird-tray-error"
	notifyIDSessionExpired = "netbird-session-expired"

	// Daemon status strings mirroring internal.Status* — kept in sync
	// with client/internal/state.go.
	statusConnected  = "Connected"
	statusConnecting = "Connecting"
	statusIdle       = "Idle"
	statusError      = "Error"
	// Daemon status string for an SSO session that has expired and needs
	// re-authentication. Mirrors internal.StatusSessionExpired.
	statusSessionExpired = "SessionExpired"
	// statusNeedsLogin is what the daemon publishes before the user has
	// completed an SSO authentication on this profile. Mirrors
	// internal.StatusNeedsLogin.
	statusNeedsLogin = "NeedsLogin"
	// statusLoginFailed is what the daemon publishes when a login attempt
	// failed with a non-auth error (management unreachable, init error,
	// etc.). The CLI groups it with NeedsLogin/SessionExpired and prompts
	// the user to run "netbird up", so we mirror that here. Mirrors
	// internal.StatusLoginFailed.
	statusLoginFailed = "LoginFailed"

	// External URLs.
	urlGitHubRepo     = "https://github.com/netbirdio/netbird"
	urlGitHubReleases = "https://github.com/netbirdio/netbird/releases/latest"
)

// Tray builds and updates the systray menu. It mirrors the layout of the Fyne
// systray 1:1 and routes clicks back to the gRPC services. Dynamic state
// (status icon, exit-node submenu) is driven by the netbird:status event.
// TrayServices bundles the daemon-RPC and notification services the tray
// menu needs. Grouped into a single struct so NewTray stays under the
// linter's parameter-count threshold and so adding another service later
// is a one-line struct change instead of a NewTray signature break.
type TrayServices struct {
	Connection *services.Connection
	Settings   *services.Settings
	Profiles   *services.Profiles
	Peers      *services.Peers
	Notifier   *notifications.NotificationService
	Update     *services.Update
}

type Tray struct {
	app    *application.App
	tray   *application.SystemTray
	window *application.WebviewWindow
	svc    TrayServices

	menu              *application.Menu
	statusItem        *application.MenuItem
	upItem            *application.MenuItem
	downItem          *application.MenuItem
	exitNodeItem      *application.MenuItem
	networksItem      *application.MenuItem
	profileSubmenu    *application.Menu
	settingsItem      *application.MenuItem
	debugItem         *application.MenuItem
	updateItem        *application.MenuItem
	daemonVersionItem *application.MenuItem

	mu                   sync.Mutex
	connected            bool
	hasUpdate            bool
	updateVersion        string
	updateEnforced       bool
	exitNodes            []string
	lastStatus           string
	lastDaemonVersion    string
	notificationsEnabled bool
	activeProfile        string
	activeUsername       string
}

func NewTray(app *application.App, window *application.WebviewWindow, svc TrayServices) *Tray {
	t := &Tray{
		app:                  app,
		window:               window,
		svc:                  svc,
		notificationsEnabled: true,
	}
	t.tray = app.SystemTray.New()
	t.applyIcon()
	t.tray.SetTooltip(trayTooltip)
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
	app.Event.On(services.EventUpdateAvailable, t.onUpdateAvailable)
	app.Event.On(services.EventUpdateProgress, t.onUpdateProgress)
	// Defer the first profile load until the macOS/GTK/Win32 menu impl is
	// live — Menu.Update() short-circuits while app.running is false, and
	// AppKit's main queue isn't ready earlier either (see d23ef34 InvokeSync
	// nil-deref).
	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		go t.loadProfiles()
	})

	go t.loadConfig()
	return t
}

// ShowWindow brings the main window forward — used by SIGUSR1 / Windows event.
// Show() alone is not enough on macOS: makeKeyAndOrderFront skips app
// activation, so a tray-style app's window pops up behind the currently
// active app. Focus() additionally calls activateIgnoringOtherApps:YES on
// macOS and SetForegroundWindow on Windows.
func (t *Tray) ShowWindow() {
	if t.window == nil {
		return
	}
	t.window.Show()
	t.window.Focus()
}

func (t *Tray) buildMenu() *application.Menu {
	menu := application.NewMenu()

	// statusItem doubles as the "Login" entry once the daemon reports
	// NeedsLogin/SessionExpired — applyStatus toggles its enabled state and
	// label. The click handler is harmless while disabled, so we wire it
	// up unconditionally rather than swapping items at runtime.
	t.statusItem = menu.Add(menuStatusDisconnected).
		OnClick(func(*application.Context) { t.openRoute("/login") }).
		SetEnabled(false).
		SetBitmap(iconMenuDotIdle)

	menu.AddSeparator()
	// The tray icon's left-click handler is intentionally unbound (see
	// NewTray for the rationale), so expose the window through an explicit
	// menu entry on every platform.
	menu.Add(menuOpenNetBird).OnClick(func(*application.Context) { t.ShowWindow() })
	menu.AddSeparator()
	// Profiles submenu is populated asynchronously once the application
	// has started — Menu.Update() is a no-op before app.running is true,
	// so the initial fill is gated on the ApplicationStarted hook.
	t.profileSubmenu = menu.AddSubmenu(menuProfiles)
	menu.AddSeparator()
	// Only the action that applies to the current state is visible: Connect
	// when disconnected, Disconnect when connected. applyStatus swaps them on
	// each daemon status change.
	t.upItem = menu.Add(menuConnect).OnClick(func(*application.Context) { t.handleConnect() })
	t.downItem = menu.Add(menuDisconnect).OnClick(func(*application.Context) { t.handleDisconnect() })
	t.downItem.SetHidden(true)

	menu.AddSeparator()

	t.exitNodeItem = menu.Add(menuExitNode).SetEnabled(false)
	t.networksItem = menu.Add(menuNetworks).OnClick(func(*application.Context) { t.openRoute("/networks") })

	menu.AddSeparator()

	// Settings, runtime toggles (SSH, Quantum-Resistance, lazy connection,
	// block-inbound, auto-connect, notifications) and profile switching
	// all live in the in-window Settings page now. The tray menu only
	// surfaces the day-to-day actions.
	t.settingsItem = menu.Add(menuSettings).OnClick(func(*application.Context) { t.openRoute("/settings") })
	t.debugItem = menu.Add(menuCreateDebugBundle).OnClick(func(*application.Context) { t.openRoute("/debug") })

	menu.AddSeparator()

	about := menu.AddSubmenu(menuAbout)
	about.Add(menuGitHub).OnClick(func(*application.Context) {
		_ = t.app.Browser.OpenURL(urlGitHubRepo)
	})
	about.Add(menuDocumentation).SetEnabled(false)
	// Disabled informational entries: the GUI version is baked in at
	// build time via -ldflags, the daemon version comes from the first
	// Status snapshot and is updated in applyStatus.
	about.Add(fmt.Sprintf(menuGUIVersionFmt, version.NetbirdVersion())).SetEnabled(false)
	t.daemonVersionItem = about.Add(fmt.Sprintf(menuDaemonVersionFmt, menuVersionUnknown)).SetEnabled(false)
	// Hidden until the daemon emits EventUpdateAvailable. The label is
	// rewritten in onUpdateAvailable to match the legacy Fyne UI:
	// menuDownloadLatestVersion for opt-in, menuInstallVersionPrefix+version
	// when the management server enforces the update.
	t.updateItem = about.Add(menuDownloadLatestVersion).OnClick(func(*application.Context) { t.handleUpdate() })
	t.updateItem.SetHidden(true)

	menu.AddSeparator()
	menu.Add(menuQuit).OnClick(func(*application.Context) { t.app.Quit() })

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
	t.upItem.SetEnabled(false)
	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := t.svc.Connection.Up(ctx, services.UpParams{}); err != nil {
			log.Errorf("connect: %v", err)
			t.notifyError(notifyErrorConnect)
			t.upItem.SetEnabled(true)
		}
	}()
}

func (t *Tray) handleDisconnect() {
	t.downItem.SetEnabled(false)
	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := t.svc.Connection.Down(ctx); err != nil {
			log.Errorf("disconnect: %v", err)
			t.notifyError(notifyErrorDisconnect)
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
// gate. The narrowly-scoped EventUpdate* events are skipped here because
// onUpdateAvailable already produces a richer notification for them.
func (t *Tray) onSystemEvent(ev *application.CustomEvent) {
	se, ok := ev.Data.(services.SystemEvent)
	if !ok || se.UserMessage == "" {
		return
	}
	if _, isUpdate := se.Metadata["new_version_available"]; isUpdate {
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

	body := se.UserMessage
	if id := se.Metadata["id"]; id != "" {
		body += fmt.Sprintf(" ID: %s", id)
	}
	t.notify(eventTitle(se), body, notifyIDEvent+se.ID)
}

// onUpdateAvailable runs when the daemon reports a new netbird version. It
// flips the tray's hasUpdate flag (icon swap), reveals the update menu
// item with the right label, and posts an OS notification.
// The notification is what the legacy Fyne UI used to alert the user.
func (t *Tray) onUpdateAvailable(ev *application.CustomEvent) {
	upd, ok := ev.Data.(services.UpdateAvailable)
	if !ok {
		log.Warnf("update event payload not UpdateAvailable: %T", ev.Data)
		return
	}
	log.Infof("tray onUpdateAvailable: version=%s enforced=%v", upd.Version, upd.Enforced)
	t.mu.Lock()
	t.hasUpdate = true
	t.updateVersion = upd.Version
	t.updateEnforced = upd.Enforced
	t.mu.Unlock()
	t.applyIcon()

	if t.updateItem != nil {
		// Match the Fyne wording: enforced updates name the version
		// because the install starts on click; opt-in updates just
		// route the user to the latest release.
		if upd.Enforced {
			t.updateItem.SetLabel(menuInstallVersionPrefix + upd.Version)
		} else {
			t.updateItem.SetLabel(menuDownloadLatestVersion)
		}
		t.updateItem.SetHidden(false)
	}

	body := fmt.Sprintf(notifyUpdateBodyFmt, upd.Version)
	if upd.Enforced {
		body += notifyUpdateEnforcedSuffix
	}
	if err := t.svc.Notifier.SendNotification(notifications.NotificationOptions{
		ID:    notifyIDUpdatePrefix + upd.Version,
		Title: notifyUpdateTitle,
		Body:  body,
	}); err != nil {
		log.Debugf("send update notification: %v", err)
	}
}

// handleUpdate runs when the user clicks the "Download latest version" /
// "Install version X" menu item. Enforced updates trigger the daemon's
// installer flow and surface the in-window /update progress page;
// opt-in updates just open the GitHub releases page in the browser.
func (t *Tray) handleUpdate() {
	t.mu.Lock()
	enforced := t.updateEnforced
	updateVersion := t.updateVersion
	t.mu.Unlock()

	if !enforced {
		_ = t.app.Browser.OpenURL(urlGitHubReleases)
		return
	}

	// Surface the progress page first so the user sees the install
	// kick off; the daemon then drives the rest via the InstallerResult
	// RPC the /update page is polling.
	if t.window != nil {
		url := "/#/update"
		if updateVersion != "" {
			url += "?version=" + updateVersion
		}
		t.window.SetURL(url)
		t.window.Show()
		t.window.Focus()
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := t.svc.Update.Trigger(ctx); err != nil {
			log.Errorf("trigger update: %v", err)
		}
	}()
}

// onUpdateProgress runs when the daemon enters the install phase of an
// enforced update. The Fyne UI used to spawn a separate process with the
// update window; here the window is already in-process, so we just route to
// the /update page and bring it forward.
func (t *Tray) onUpdateProgress(ev *application.CustomEvent) {
	prog, ok := ev.Data.(services.UpdateProgress)
	if !ok || prog.Action != "show" {
		return
	}
	if t.window == nil {
		return
	}
	url := "/#/update"
	if prog.Version != "" {
		url += "?version=" + prog.Version
	}
	t.window.SetURL(url)
	t.window.Show()
	t.window.Focus()
}

// applyStatus updates the tray icon, status label, exit-node submenu, and
// connect/disconnect enablement based on the latest daemon snapshot.
// Skips the icon refresh when none of the icon-relevant inputs
// (connected, hasUpdate, status label) changed — the daemon emits
// rapid SubscribeStatus bursts during health probes that would
// otherwise spam Shell_NotifyIcon and the log.
func (t *Tray) applyStatus(st services.Status) {
	t.mu.Lock()
	connected := strings.EqualFold(st.Status, statusConnected)
	iconChanged := connected != t.connected || st.Status != t.lastStatus
	// Detect the transition into SessionExpired: the daemon emits the
	// state on every Status snapshot for as long as the session stays
	// expired, so without this guard we would re-fire the notification
	// on every push. Mirrors the legacy Fyne client's sendNotification
	// flag in onSessionExpire.
	sessionExpiredEnter := strings.EqualFold(st.Status, statusSessionExpired) &&
		!strings.EqualFold(t.lastStatus, statusSessionExpired)
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

	if iconChanged {
		t.applyIcon()
		needsLogin := strings.EqualFold(st.Status, statusNeedsLogin) ||
			strings.EqualFold(st.Status, statusSessionExpired) ||
			strings.EqualFold(st.Status, statusLoginFailed)
		daemonUnavailable := strings.EqualFold(st.Status, services.StatusDaemonUnavailable)
		connecting := strings.EqualFold(st.Status, statusConnecting)
		if t.statusItem != nil {
			// When the daemon needs re-authentication the status row turns
			// into the actionable Login entry — Connect would only fail.
			// When the daemon socket is unreachable, swap the label to make
			// the cause obvious; Connect/Disconnect would just fail.
			label := st.Status
			switch {
			case daemonUnavailable:
				label = menuStatusDaemonUnavailable
			case strings.EqualFold(st.Status, statusIdle):
				label = menuStatusDisconnected
			}
			t.statusItem.SetLabel(label)
			t.statusItem.SetEnabled(needsLogin)
			t.applyStatusIndicator(st.Status)
		}
		if t.upItem != nil {
			// Hide Connect whenever an Up action would be a no-op or would
			// only fail: tunnel already up, daemon mid-connect (Disconnect
			// takes over the slot so the user can abort), login required,
			// or daemon socket unreachable.
			t.upItem.SetHidden(connected || connecting || needsLogin || daemonUnavailable)
			t.upItem.SetEnabled(!connected && !connecting && !needsLogin && !daemonUnavailable)
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
	}
	if exitNodesChanged {
		t.rebuildExitNodes(exitNodes)
	}
	if daemonVersionChanged && t.daemonVersionItem != nil {
		t.daemonVersionItem.SetLabel(fmt.Sprintf(menuDaemonVersionFmt, st.DaemonVersion))
	}
	if sessionExpiredEnter {
		t.handleSessionExpired()
	}
}

// handleSessionExpired surfaces the SSO re-authentication path when the
// daemon reports StatusSessionExpired. Posts a single OS notification
// (the applyStatus guard ensures it fires only on the transition, not
// on every status snapshot) and brings the main window forward so the
// frontend's /login route can drive the renewed SSO flow. Mirrors the
// Fyne client's onSessionExpire, which used a runSelfCommand to spawn
// the login-url helper; here the window is already in-process.
func (t *Tray) handleSessionExpired() {
	t.notify(notifySessionExpiredTitle, notifySessionExpiredBody, notifyIDSessionExpired)
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
func (t *Tray) applyStatusIndicator(status string) {
	if t.statusItem == nil {
		return
	}
	t.statusItem.SetBitmap(statusIndicatorBitmap(status))
}

func statusIndicatorBitmap(status string) []byte {
	switch {
	case strings.EqualFold(status, statusConnected):
		return iconMenuDotConnected
	case strings.EqualFold(status, statusConnecting):
		return iconMenuDotConnecting
	case strings.EqualFold(status, statusNeedsLogin),
		strings.EqualFold(status, statusSessionExpired):
		return iconMenuDotLogin
	case strings.EqualFold(status, statusLoginFailed),
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
	hasUpdate := t.hasUpdate
	statusLabel := t.lastStatus
	t.mu.Unlock()

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
	hasUpdate := t.hasUpdate
	statusLabel := t.lastStatus
	t.mu.Unlock()

	connecting := strings.EqualFold(statusLabel, statusConnecting)
	errored := strings.EqualFold(statusLabel, statusError) ||
		strings.EqualFold(statusLabel, services.StatusDaemonUnavailable)
	needsLogin := strings.EqualFold(statusLabel, statusNeedsLogin) ||
		strings.EqualFold(statusLabel, statusSessionExpired) ||
		strings.EqualFold(statusLabel, statusLoginFailed)

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
// Called once on ApplicationStarted and again after a successful switch
// so the checkmark moves to the new active profile.
func (t *Tray) loadProfiles() {
	if t.profileSubmenu == nil {
		return
	}
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
	for _, p := range profiles {
		name := p.Name
		active := p.IsActive
		log.Infof("tray loadProfiles: profile=%q active=%v", name, active)
		item := t.profileSubmenu.AddCheckbox(name, active)
		item.OnClick(func(*application.Context) {
			log.Infof("tray profile click: profile=%q wasActive=%v", name, active)
			if active {
				return
			}
			t.switchProfile(name)
		})
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

// switchProfile runs the daemon RPC in a goroutine so the menu click
// returns immediately, then reloads the submenu to move the checkmark.
//
// Reconnect policy by previous daemon status:
//
//	┌─────────────────┬──────────────────────┬───────────────────────────────────┐
//	│ Previous status │ Tray action          │ Rationale                         │
//	├─────────────────┼──────────────────────┼───────────────────────────────────┤
//	│ Connected       │ Switch + Down + Up   │ Reconnect with the new profile.   │
//	│ Connecting      │ Switch + Down + Up   │ Stop the retry loop still dialing │
//	│                 │                      │ the old management server, then   │
//	│                 │                      │ restart with new config.          │
//	│ Idle            │ Switch only          │ User chose to be offline; don't   │
//	│                 │                      │ silently flip the daemon online.  │
//	│ NeedsLogin      │ Switch only          │ Login needs interactive SSO; let  │
//	│ LoginFailed     │ Switch only          │ the user trigger the next step.   │
//	│ SessionExpired  │ Switch only          │                                   │
//	└─────────────────┴──────────────────────┴───────────────────────────────────┘
//
// Rule of thumb: auto-reconnect only when the daemon was actively trying
// to be online (Connected or Connecting). Any other state is a deliberate
// waiting point — keep the user in control of the next action.
func (t *Tray) switchProfile(name string) {
	t.mu.Lock()
	prevStatus := t.lastStatus
	t.mu.Unlock()
	wasActive := strings.EqualFold(prevStatus, statusConnected) ||
		strings.EqualFold(prevStatus, statusConnecting)

	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		username, err := t.svc.Profiles.Username()
		if err != nil {
			log.Errorf("get current user: %v", err)
			return
		}
		log.Infof("tray switchProfile: sending SwitchProfile RPC profile=%q user=%q prevStatus=%q wasActive=%v",
			name, username, prevStatus, wasActive)
		if err := t.svc.Profiles.Switch(ctx, services.ProfileRef{
			ProfileName: name,
			Username:    username,
		}); err != nil {
			log.Errorf("tray switchProfile: SwitchProfile RPC failed profile=%q err=%v", name, err)
			t.notifyError(fmt.Sprintf("Failed to switch to %s", name))
			return
		}
		log.Infof("tray switchProfile: SwitchProfile RPC succeeded profile=%q", name)

		if wasActive {
			// Stop the in-flight (or established) connection that's still
			// pointing at the previous profile's management server, then
			// bring it back up against the new profile.
			log.Infof("tray switchProfile: was active (%s), reconnecting with new profile %q", prevStatus, name)
			if err := t.svc.Connection.Down(ctx); err != nil {
				log.Errorf("tray switchProfile: Down failed: %v", err)
			}
			if err := t.svc.Connection.Up(ctx, services.UpParams{
				ProfileName: name,
				Username:    username,
			}); err != nil {
				log.Errorf("tray switchProfile: Up failed: %v", err)
				t.notifyError(fmt.Sprintf("Failed to reconnect with %s", name))
			}
		}

		t.loadProfiles()
	}()
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

// notifyError fires a generic "Error" notification for tray-driven action
// failures. Each tray click site already logs the underlying error; this
// adds the user-visible toast.
func (t *Tray) notifyError(message string) {
	t.notify(notifyErrorTitle, message, notifyIDTrayError)
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
