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
	"github.com/wailsapp/wails/v3/pkg/services/notifications"

	"github.com/netbirdio/netbird/client/ui-wails/services"
)

// User-facing strings exposed in the tray, OS notifications and the
// browser-opened URLs. Centralised here so future copy edits and (one
// day) localisation have a single source of truth.
const (
	trayTooltip = "NetBird"

	// Top-level menu entries.
	menuStatusDisconnected = "Disconnected"
	menuOpenNetBird        = "Open NetBird"
	menuConnect            = "Connect"
	menuDisconnect         = "Disconnect"
	menuExitNode           = "Exit Node"
	menuNetworks           = "Networks"
	menuQuit               = "Quit"

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

	// OS notifications.
	notifyUpdateTitle          = "NetBird update available"
	notifyUpdateBodyFmt        = "NetBird %s is available."
	notifyUpdateEnforcedSuffix = " Your administrator requires this update."
	notifyErrorTitle           = "Error"
	notifyErrorConnect         = "Failed to connect"
	notifyErrorDisconnect      = "Failed to disconnect"

	// Notification IDs (used to coalesce duplicate toasts).
	notifyIDUpdatePrefix = "netbird-update-"
	notifyIDEvent        = "netbird-event-"
	notifyIDTrayError    = "netbird-tray-error"

	// External URLs.
	urlGitHubRepo     = "https://github.com/netbirdio/netbird"
	urlGitHubReleases = "https://github.com/netbirdio/netbird/releases/latest"
)

// Tray builds and updates the systray menu. It mirrors the layout of the Fyne
// systray 1:1 and routes clicks back to the gRPC services. Dynamic state
// (status icon, exit-node submenu) is driven by the netbird:status event.
type Tray struct {
	app        *application.App
	tray       *application.SystemTray
	window     *application.WebviewWindow
	connection *services.Connection
	settings   *services.Settings
	profiles   *services.Profiles
	peers      *services.Peers
	notifier   *notifications.NotificationService
	update     *services.Update

	statusItem   *application.MenuItem
	upItem       *application.MenuItem
	downItem     *application.MenuItem
	exitNodeItem *application.MenuItem
	networksItem *application.MenuItem
	updateItem   *application.MenuItem

	mu                   sync.Mutex
	connected            bool
	hasUpdate            bool
	updateVersion        string
	updateEnforced       bool
	exitNodes            []string
	lastStatus           string
	notificationsEnabled bool
	activeProfile        string
	activeUsername       string
}

func NewTray(
	app *application.App,
	window *application.WebviewWindow,
	connection *services.Connection,
	settings *services.Settings,
	profiles *services.Profiles,
	peers *services.Peers,
	notifier *notifications.NotificationService,
	update *services.Update,
) *Tray {
	t := &Tray{
		app:                  app,
		window:               window,
		connection:           connection,
		settings:             settings,
		profiles:             profiles,
		peers:                peers,
		notifier:             notifier,
		update:               update,
		notificationsEnabled: true,
	}
	t.tray = app.SystemTray.New()
	t.applyIcon()
	t.tray.SetTooltip(trayTooltip)
	t.tray.SetMenu(t.buildMenu())
	// Tray click handling is platform-specific by design:
	//
	// On Windows and macOS the OS-level tray protocol cleanly separates left
	// and right click. AttachWindow plus an explicit OnClick gives the
	// expected "click the icon to toggle the window, right-click to open the
	// menu" UX, and the platform never delivers both events at once.
	//
	// On Linux the tray rides on the org.kde.StatusNotifierItem D-Bus protocol
	// (libayatana-appindicator). The SNI Activate signal *is* left-click, but
	// several environments — GNOME Shell with the AppIndicator extension is
	// the loudest offender — also pop the attached menu on left-click,
	// regardless of the ItemIsMenu property the spec defines for that purpose.
	// Worse, AttachWindow on its own is enough to trigger this: Wails3's
	// SystemTray.applySmartDefaults installs ToggleWindow as the default
	// click handler whenever a window is attached, so even without an
	// explicit OnClick the window pops up alongside the menu. The result
	// looks like a bug to users.
	//
	// Mirror the legacy Fyne client's behaviour on Linux: skip both
	// AttachWindow and OnClick so left-click only opens the menu, and expose
	// the window through an explicit "Open NetBird" item. Right-click still
	// opens the menu through Wails' default rightClickHandler fallback.
	if runtime.GOOS != "linux" {
		t.tray.AttachWindow(window)
		t.tray.OnClick(func() { t.toggleWindow() })
	}

	app.Event.On(services.EventStatus, t.onStatusEvent)
	app.Event.On(services.EventSystem, t.onSystemEvent)
	app.Event.On(services.EventUpdateAvailable, t.onUpdateAvailable)
	app.Event.On(services.EventUpdateProgress, t.onUpdateProgress)

	go t.loadConfig()
	return t
}

// ShowWindow brings the main window forward — used by SIGUSR1 / Windows event.
func (t *Tray) ShowWindow() {
	if t.window == nil {
		return
	}
	t.window.Show()
}

func (t *Tray) buildMenu() *application.Menu {
	menu := application.NewMenu()

	t.statusItem = menu.Add(menuStatusDisconnected).SetEnabled(false)

	menu.AddSeparator()
	// On Linux the tray icon's left-click handler is intentionally unbound
	// (see NewTray for the rationale), so expose the window through an
	// explicit menu entry. Windows and macOS get the window via left-click.
	if runtime.GOOS == "linux" {
		menu.Add(menuOpenNetBird).OnClick(func(*application.Context) { t.ShowWindow() })
		menu.AddSeparator()
	}
	t.upItem = menu.Add(menuConnect).OnClick(func(*application.Context) { t.handleConnect() })
	t.downItem = menu.Add(menuDisconnect).OnClick(func(*application.Context) { t.handleDisconnect() })
	t.downItem.SetEnabled(false)

	menu.AddSeparator()

	t.exitNodeItem = menu.Add(menuExitNode).SetEnabled(false)
	t.networksItem = menu.Add(menuNetworks).OnClick(func(*application.Context) { t.openRoute("/networks") })

	menu.AddSeparator()

	// Settings, runtime toggles (SSH, Quantum-Resistance, lazy connection,
	// block-inbound, auto-connect, notifications) and profile switching
	// all live in the in-window Settings page now. The tray menu only
	// surfaces the day-to-day actions.
	menu.Add(menuSettings).OnClick(func(*application.Context) { t.openRoute("/settings") })
	menu.Add(menuCreateDebugBundle).OnClick(func(*application.Context) { t.openRoute("/debug") })

	menu.AddSeparator()

	about := menu.AddSubmenu(menuAbout)
	about.Add(menuGitHub).OnClick(func(*application.Context) {
		_ = t.app.Browser.OpenURL(urlGitHubRepo)
	})
	about.Add(menuDocumentation).SetEnabled(false)
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

func (t *Tray) toggleWindow() {
	if t.window == nil {
		return
	}
	if t.window.IsVisible() {
		t.window.Hide()
		return
	}
	t.window.Show()
}

func (t *Tray) openRoute(route string) {
	if t.window == nil {
		return
	}
	t.window.Show()
	t.window.SetURL("/#" + route)
}

func (t *Tray) handleConnect() {
	t.upItem.SetEnabled(false)
	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := t.connection.Up(ctx, services.UpParams{}); err != nil {
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
		if err := t.connection.Down(ctx); err != nil {
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
	if err := t.notifier.SendNotification(notifications.NotificationOptions{
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
	version := t.updateVersion
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
		if version != "" {
			url += "?version=" + version
		}
		t.window.SetURL(url)
		t.window.Show()
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := t.update.Trigger(ctx); err != nil {
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
}

// applyStatus updates the tray icon, status label, exit-node submenu, and
// connect/disconnect enablement based on the latest daemon snapshot.
// Skips the icon refresh when none of the icon-relevant inputs
// (connected, hasUpdate, status label) changed — the daemon emits
// rapid SubscribeStatus bursts during health probes that would
// otherwise spam Shell_NotifyIcon and the log.
func (t *Tray) applyStatus(st services.Status) {
	t.mu.Lock()
	connected := strings.EqualFold(st.Status, "Connected")
	iconChanged := connected != t.connected || st.Status != t.lastStatus
	t.connected = connected
	t.lastStatus = st.Status

	exitNodes := exitNodesFromStatus(st)
	exitNodesChanged := !equalStrings(exitNodes, t.exitNodes)
	t.exitNodes = exitNodes
	t.mu.Unlock()

	if iconChanged {
		t.applyIcon()
		if t.statusItem != nil {
			t.statusItem.SetLabel(st.Status)
		}
		if t.upItem != nil {
			t.upItem.SetEnabled(!connected)
		}
		if t.downItem != nil {
			t.downItem.SetEnabled(connected)
		}
	}
	if exitNodesChanged {
		t.rebuildExitNodes(exitNodes)
	}
}

func (t *Tray) rebuildExitNodes(nodes []string) {
	if t.exitNodeItem == nil {
		return
	}
	if len(nodes) == 0 {
		t.exitNodeItem.SetEnabled(false)
		return
	}
	sub := application.NewMenu()
	for _, fqdn := range nodes {
		sub.AddCheckbox(fqdn, false)
	}
	t.exitNodeItem.SetEnabled(true)
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

	connecting := strings.EqualFold(statusLabel, "Connecting")
	errored := strings.EqualFold(statusLabel, "Error")

	if runtime.GOOS == "darwin" {
		switch {
		case connecting:
			return iconConnectingMacOS, nil
		case errored:
			return iconErrorMacOS, nil
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

	active, err := t.profiles.GetActive(ctx)
	if err != nil {
		log.Debugf("get active profile: %v", err)
		return
	}
	cfg, err := t.settings.GetConfig(ctx, services.ConfigParams(active))
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

// notify wraps the Wails notification service with the tray's standard
// id-prefix scheme and swallows errors (notifications are best-effort).
func (t *Tray) notify(title, body, id string) {
	if t.notifier == nil {
		return
	}
	if err := t.notifier.SendNotification(notifications.NotificationOptions{
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
