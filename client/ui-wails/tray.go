//go:build !android && !ios && !freebsd && !js

package main

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/services/notifications"

	"github.com/netbirdio/netbird/client/ui-wails/services"
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

	statusItem    *application.MenuItem
	upItem        *application.MenuItem
	downItem      *application.MenuItem
	exitNodeItem  *application.MenuItem
	networksItem  *application.MenuItem
	allowSSHItem  *application.MenuItem
	autoConnItem  *application.MenuItem
	rosenpassItem *application.MenuItem
	lazyConnItem  *application.MenuItem
	blockInItem   *application.MenuItem
	notifyItem    *application.MenuItem

	mu                   sync.Mutex
	connected            bool
	hasUpdate            bool
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
) *Tray {
	t := &Tray{
		app:                  app,
		window:               window,
		connection:           connection,
		settings:             settings,
		profiles:             profiles,
		peers:                peers,
		notifier:             notifier,
		notificationsEnabled: true,
	}
	t.tray = app.SystemTray.New()
	t.applyIcon()
	t.tray.SetTooltip("NetBird")
	t.tray.SetMenu(t.buildMenu())
	t.tray.AttachWindow(window)
	t.tray.OnClick(func() { t.toggleWindow() })

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

	t.statusItem = menu.Add("Disconnected").SetEnabled(false)

	menu.AddSeparator()
	t.upItem = menu.Add("Connect").OnClick(func(*application.Context) { t.handleConnect() })
	t.downItem = menu.Add("Disconnect").OnClick(func(*application.Context) { t.handleDisconnect() })
	t.downItem.SetEnabled(false)

	menu.AddSeparator()

	settingsSub := menu.AddSubmenu("Settings")
	t.allowSSHItem = settingsSub.AddCheckbox("Allow SSH", false).OnClick(func(*application.Context) {
		t.flipFlag("ssh", t.allowSSHItem.Checked())
	})
	t.autoConnItem = settingsSub.AddCheckbox("Connect on Startup", false).OnClick(func(*application.Context) {
		t.flipFlag("auto", t.autoConnItem.Checked())
	})
	t.rosenpassItem = settingsSub.AddCheckbox("Enable Quantum-Resistance", false).OnClick(func(*application.Context) {
		t.flipFlag("rosenpass", t.rosenpassItem.Checked())
	})
	t.lazyConnItem = settingsSub.AddCheckbox("Enable Lazy Connections", false).OnClick(func(*application.Context) {
		t.flipFlag("lazy", t.lazyConnItem.Checked())
	})
	t.blockInItem = settingsSub.AddCheckbox("Block Inbound Connections", false).OnClick(func(*application.Context) {
		t.flipFlag("blockin", t.blockInItem.Checked())
	})
	t.notifyItem = settingsSub.AddCheckbox("Notifications", true).OnClick(func(*application.Context) {
		t.flipFlag("notify", t.notifyItem.Checked())
	})
	settingsSub.AddSeparator()
	settingsSub.Add("Advanced Settings").OnClick(func(*application.Context) { t.openRoute("/settings") })
	settingsSub.Add("Create Debug Bundle").OnClick(func(*application.Context) { t.openRoute("/debug") })

	t.exitNodeItem = menu.Add("Exit Node").SetEnabled(false)

	t.networksItem = menu.Add("Networks").OnClick(func(*application.Context) { t.openRoute("/networks") })

	menu.AddSeparator()

	about := menu.AddSubmenu("About")
	about.Add("GitHub").OnClick(func(*application.Context) {
		_ = t.app.Browser.OpenURL("https://github.com/netbirdio/netbird")
	})
	about.Add("Documentation").SetEnabled(false)

	menu.AddSeparator()
	menu.Add("Quit").OnClick(func(*application.Context) { t.app.Quit() })

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
			t.notifyError("Failed to connect")
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
			t.notifyError("Failed to disconnect")
			t.downItem.SetEnabled(true)
		}
	}()
}

// flipFlag pushes a partial SetConfig for one tray-toggled boolean. On
// failure the tray checkbox is reverted to keep it in sync with the daemon
// and an error notification is fired so the user knows the change didn't
// stick. The "notify" flag also updates the in-process gate that decides
// whether daemon SystemEvents become OS notifications.
func (t *Tray) flipFlag(name string, checked bool) {
	go func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		t.mu.Lock()
		profile, username := t.activeProfile, t.activeUsername
		t.mu.Unlock()

		req := services.SetConfigParams{ProfileName: profile, Username: username}
		var (
			label string
			item  *application.MenuItem
		)
		switch name {
		case "ssh":
			req.ServerSSHAllowed = ptrBool(checked)
			label, item = "SSH", t.allowSSHItem
		case "auto":
			// "Connect on Startup" is the inverse of disableAutoConnect.
			req.DisableAutoConnect = ptrBool(!checked)
			label, item = "auto-connect", t.autoConnItem
		case "rosenpass":
			req.RosenpassEnabled = ptrBool(checked)
			label, item = "Rosenpass", t.rosenpassItem
		case "lazy":
			req.LazyConnectionEnabled = ptrBool(checked)
			label, item = "lazy connection", t.lazyConnItem
		case "blockin":
			req.BlockInbound = ptrBool(checked)
			label, item = "block inbound", t.blockInItem
		case "notify":
			req.DisableNotifications = ptrBool(!checked)
			label, item = "notifications", t.notifyItem
		default:
			log.Debugf("tray flipFlag: unknown flag %q", name)
			return
		}

		if err := t.settings.SetConfig(ctx, req); err != nil {
			log.Errorf("set %s: %v", label, err)
			t.notifyError("Failed to update " + label + " settings")
			if item != nil {
				item.SetChecked(!checked) // revert
			}
			return
		}

		if name == "notify" {
			t.mu.Lock()
			t.notificationsEnabled = checked
			t.mu.Unlock()
		}
	}()
}

func ptrBool(b bool) *bool { return &b }

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
	t.notify(eventTitle(se), body, "netbird-event-"+se.ID)
}

// onUpdateAvailable runs when the daemon reports a new netbird version. It
// flips the tray's hasUpdate flag (icon swap) and posts an OS notification.
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
	t.mu.Unlock()
	t.applyIcon()

	body := fmt.Sprintf("NetBird %s is available.", upd.Version)
	if upd.Enforced {
		body += " Your administrator requires this update."
	}
	if err := t.notifier.SendNotification(notifications.NotificationOptions{
		ID:    "netbird-update-" + upd.Version,
		Title: "NetBird update available",
		Body:  body,
	}); err != nil {
		log.Debugf("send update notification: %v", err)
	}
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

// loadConfig syncs the tray-submenu checkboxes with the daemon's stored
// config and seeds the notifications gate. Called once at startup from a
// goroutine so a slow or unreachable daemon does not block menu construction.
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

	if t.allowSSHItem != nil {
		t.allowSSHItem.SetChecked(cfg.ServerSSHAllowed)
	}
	if t.autoConnItem != nil {
		t.autoConnItem.SetChecked(!cfg.DisableAutoConnect)
	}
	if t.rosenpassItem != nil {
		t.rosenpassItem.SetChecked(cfg.RosenpassEnabled)
	}
	if t.lazyConnItem != nil {
		t.lazyConnItem.SetChecked(cfg.LazyConnectionEnabled)
	}
	if t.blockInItem != nil {
		t.blockInItem.SetChecked(cfg.BlockInbound)
	}
	if t.notifyItem != nil {
		t.notifyItem.SetChecked(!cfg.DisableNotifications)
	}
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
	t.notify("Error", message, "netbird-tray-error")
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

