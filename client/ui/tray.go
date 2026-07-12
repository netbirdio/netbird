//go:build !android && !ios && !freebsd && !js

package main

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
	"github.com/wailsapp/wails/v3/pkg/services/notifications"

	"github.com/netbirdio/netbird/client/ui/authsession"
	"github.com/netbirdio/netbird/client/ui/i18n"
	"github.com/netbirdio/netbird/client/ui/services"
	"github.com/netbirdio/netbird/version"
)

// Notification IDs are OS dedup keys that coalesce duplicate toasts;
// statusError is a tray-only sentinel for the error-icon state.
const (
	notifyIDUpdatePrefix = "netbird-update-"
	notifyIDEvent        = "netbird-event-"
	notifyIDTrayError    = "netbird-tray-error"
	notifyIDMDMPolicy    = "netbird-mdm-policy"

	statusError = "Error"

	urlGitHubRepo     = "https://github.com/netbirdio/netbird"
	urlGitHubReleases = "https://github.com/netbirdio/netbird/releases/latest"
	urlDocs           = "https://docs.netbird.io"
)

// TrayServices bundles the services the tray menu needs, grouped so NewTray
// stays under the linter's parameter-count threshold.
type TrayServices struct {
	Connection      *services.Connection
	Settings        *services.Settings
	Profiles        *services.Profiles
	Networks        *services.Networks
	DaemonFeed      *services.DaemonFeed
	Notifier        *notifications.NotificationService
	Update          *services.Update
	ProfileSwitcher *services.ProfileSwitcher
	WindowManager   *services.WindowManager
	// Session is bound to authsession directly because the services wrapper
	// only re-exposes the React subset.
	Session   *authsession.Session
	Localizer *Localizer
}

type Tray struct {
	app    *application.App
	tray   *application.SystemTray
	window *application.WebviewWindow
	svc    TrayServices
	// panelDark reports whether the desktop panel uses a dark scheme, so
	// iconForState can pick the black vs white mono tray icon on Linux. Set
	// by startTrayTheme (Linux only); nil elsewhere, where panelIsDark falls
	// back to its default.
	panelDark func() bool
	loc       *Localizer

	// menu and the *Item/*Submenu fields below are reassigned by buildMenu
	// on every relayout — touch them only with menuMu held. Exceptions:
	// the Connect/Disconnect OnClick closures capture their own item, and
	// refreshSessionExpiresLabel snapshots its item under menuMu.
	menu       *application.Menu
	statusItem *application.MenuItem
	// sessionExpiresItem shows the SSO deadline as a remaining-time label,
	// repainted by a 30s ticker.
	sessionExpiresItem *application.MenuItem
	upItem             *application.MenuItem
	downItem           *application.MenuItem
	exitNodeItem       *application.MenuItem
	exitNodeSubmenu    *application.Menu
	profileSubmenu     *application.Menu
	profileSubmenuItem *application.MenuItem
	profileEmailItem   *application.MenuItem
	settingsItem       *application.MenuItem
	daemonVersionItem  *application.MenuItem

	updater *trayUpdater

	// statusMu guards the daemon-status core mirrored on the tray. One mutex
	// covers these fields because applyStatus writes them together on every
	// Status push and the menu painters read them.
	statusMu          sync.Mutex
	connected         bool
	lastStatus        string
	lastDaemonVersion string
	// lastNetworksRevision is the daemon's routed-networks revision; a bump (or
	// a connect/disconnect transition) gates the refreshExitNodes re-fetch so
	// ListNetworks runs only when routes change. The peer-status route list
	// can't substitute: it carries only actively-routed routes, not candidate
	// exit nodes.
	lastNetworksRevision uint64
	// pendingConnectLogin is set when handleConnect fires an Up on an idle
	// daemon. The daemon flips to NeedsLogin if the peer is SSO-tracked with
	// no cached token; applyStatus consumes the flag on that transition to
	// open the browser-login flow, saving a second Connect click.
	// Profile-switch reconnects are handled separately by
	// DaemonFeed.statusStreamLoop.
	pendingConnectLogin bool

	// sessionMu guards the cached SSO deadline used by the session row.
	// Independent of statusMu so the 30s ticker reader and the Status-push
	// writer don't block each other.
	sessionMu        sync.Mutex
	sessionExpiresAt time.Time

	// profileMu guards the profile-domain state (active identity, the
	// notifications gate, the in-flight switch cancel). Independent of
	// statusMu so a long-running switch holding switchCancel doesn't block a
	// Status-push reader of t.connected.
	profileMu            sync.Mutex
	activeProfile        string
	activeUsername       string
	notificationsEnabled bool
	switchCancel         context.CancelFunc

	// profileLoadMu serializes loadProfiles so the applyStatus refresh can't
	// race the ApplicationStarted seed or the post-switch reload — all
	// manipulate profileSubmenu + SetMenu, which Wails isn't concurrency-safe
	// against.
	profileLoadMu sync.Mutex

	// profilesMu guards the cached profile rows that relayoutMenu repaints
	// into a freshly built Profiles submenu, kept separate from the live
	// submenu so a relayout always has a source to repaint from without
	// re-hitting the daemon.
	profilesMu   sync.Mutex
	profiles     []services.Profile
	profilesUser string

	// menuMu serialises relayoutMenu (buildMenu + SetMenu) and guards the
	// menu/item-pointer fields above. relayoutMenu is the only post-startup
	// SetMenu call site — a menu snapshot pushed outside the lock could
	// reinstall a stale tree.
	menuMu sync.Mutex

	// exitNodesMu guards the exitNodes row cache so relayoutMenu's read (and
	// the Repaint copy) doesn't contend with status-push readers of statusMu.
	exitNodesMu sync.Mutex
	exitNodes   []exitNodeEntry
	// exitNodesRebuildMu serialises the ListNetworks fetch + submenu rebuild +
	// SetMenu cycle so back-to-back Status pushes can't run it concurrently
	// with itself.
	exitNodesRebuildMu sync.Mutex

	// featureMu guards the daemon feature kill switches mirrored on the tray.
	// Fetched at startup and refreshed on every config_changed event (the
	// daemon re-applies MDM policy per engine spawn), so featuresDisabled can
	// grey out menus without polling GetFeatures.
	featureMu       sync.Mutex
	disableProfiles bool
	disableNetworks bool
}

func NewTray(app *application.App, window *application.WebviewWindow, svc TrayServices) *Tray {
	t := &Tray{
		app:                  app,
		window:               window,
		svc:                  svc,
		notificationsEnabled: true,
		// Localizer is constructed by main so the first menu render is already
		// in the right locale — no English flash then re-paint.
		loc: svc.Localizer,
	}
	t.updater = newTrayUpdater(app, window, svc.Update, svc.Notifier, t.loc, func() { t.applyIcon() }, func() { t.relayoutMenu() })
	t.tray = app.SystemTray.New()
	// Seed panel-theme detection before the first paint so the initial icon
	// matches the panel's light/dark scheme (Linux only).
	t.startTrayTheme()
	t.applyIcon()
	t.tray.SetTooltip(t.loc.T("tray.tooltip"))
	// On Linux the SNI hover tooltip rides on the systray label, not
	// SetTooltip (a no-op there); without a label Wails shows the literal
	// "Wails". macOS/Windows are skipped (label paints visible text on
	// macOS; Windows uses SetTooltip above).
	if runtime.GOOS == "linux" {
		t.tray.SetLabel(t.loc.T("tray.tooltip"))
	}
	t.menu = t.buildMenu()
	t.tray.SetMenu(t.menu)
	// macOS/Linux give click→menu natively, so bindTrayClick is a no-op there
	// (binding OnClick→OpenMenu on macOS would freeze the tray); Windows has no
	// native left-click handler so it wires one to open the main window, leaving
	// the menu on right-click (see tray_click_*.go). On Linux AttachWindow is
	// skipped — with applySmartDefaults it would pop the window alongside the
	// menu (e.g. GNOME Shell AppIndicator).
	bindTrayClick(t)

	app.Event.On(services.EventStatusSnapshot, t.onStatusEvent)
	app.Event.On(services.EventDaemonNotification, t.onSystemEvent)
	// Refresh the Profiles submenu on ProfileSwitcher's change event. A
	// switch on an idle daemon drives no status transition, so without this
	// hook a React-initiated switch leaves the tray's submenu stale.
	app.Event.On(services.EventProfileChanged, func(*application.CustomEvent) {
		go t.loadProfiles()
	})
	// Defer the first profile load until the menu impl is live — Menu.Update()
	// short-circuits while app.running is false, and AppKit's main queue isn't
	// ready earlier (see d23ef34 InvokeSync nil-deref).
	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		go t.loadProfiles()
		go t.refreshRestrictions()
		go t.runSessionExpiryTicker()
		// Category registration must run after the notifications service
		// Startup populates appName/registry path on Windows; before app.Run()
		// the category lookup silently falls back to a plain notification.
		t.registerSessionWarningCategory()
	})

	t.loc.Watch(func(i18n.LanguageCode) { t.applyLanguage() })

	go t.loadConfig()
	return t
}

// ShowWindow brings the main window forward — used by SIGUSR1 / Windows event.
// Show() alone is not enough on macOS (makeKeyAndOrderFront skips activation,
// so the window pops up behind the active app); Focus() additionally calls
// activateIgnoringOtherApps:YES on macOS and SetForegroundWindow on Windows.
func (t *Tray) ShowWindow() {
	// An install supersedes every other flow, so check it before BrowserLogin.
	if w := t.svc.WindowManager.InstallProgressWindow(); w != nil {
		w.Show()
		w.Focus()
		return
	}
	if w := t.svc.WindowManager.BrowserLoginWindow(); w != nil {
		w.Show()
		w.Focus()
		return
	}
	if t.window == nil {
		return
	}
	// Route through WindowManager so the main window is centered on first
	// show — minimal WMs (fluxbox, the XEmbed tray path) otherwise drop it in
	// the top-left corner.
	if t.svc.WindowManager != nil {
		t.svc.WindowManager.ShowMain()
		return
	}
	t.window.Show()
	t.window.Focus()
}

// applyLanguage re-renders every translated surface in the Localizer's current
// language. Wails dispatches menu/tray APIs onto the UI thread internally, so
// calling them from the Localizer's background goroutine is safe; profileLoadMu
// prevents loadProfiles from racing the rebuild.
func (t *Tray) applyLanguage() {
	t.tray.SetTooltip(t.loc.T("tray.tooltip"))
	// Mirror the Linux label fix from NewTray (the SNI tooltip rides on the
	// label).
	if runtime.GOOS == "linux" {
		t.tray.SetLabel(t.loc.T("tray.tooltip"))
	}
	t.relayoutMenu()
}

// relayoutMenu rebuilds the entire tray menu, repaints the cached
// status/session/profile/exit-node state into the fresh items, and pushes the
// whole tree with a single SetMenu.
//
// A full rebuild is required because on KDE/Plasma the StatusNotifierItem host
// caches a submenu's layout on first open (GetLayout for that submenu id) and
// never re-fetches it on a LayoutUpdated(parent=0) signal — so Clear()+Add()
// into the same container froze both the visible rows and the click→id mapping,
// and stale ids no-op'd. buildMenu allocates a fresh submenu container id each
// time, which Plasma treats as unseen and re-queries (confirmed via
// dbus-monitor). This also covers the darwin detached-NSMenu workaround, since
// it rebuilds the whole tree against the cached top-level pointer.
//
// Rows come from the profilesMu/exitNodes caches, so it never re-hits the
// daemon or recurses back into loadProfiles.
func (t *Tray) relayoutMenu() {
	t.menuMu.Lock()
	defer t.menuMu.Unlock()

	t.menu = t.buildMenu()

	t.statusMu.Lock()
	connected := t.connected
	lastStatus := t.lastStatus
	daemonVersion := t.lastDaemonVersion
	t.statusMu.Unlock()

	t.sessionMu.Lock()
	sessionDeadline := t.sessionExpiresAt
	t.sessionMu.Unlock()

	t.exitNodesMu.Lock()
	exitNodeEntries := append([]exitNodeEntry(nil), t.exitNodes...)
	t.exitNodesMu.Unlock()

	disableProfiles, disableNetworks := t.featuresDisabled()

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
			remaining := t.formatSessionRemaining(time.Until(sessionDeadline))
			t.sessionExpiresItem.SetLabel(t.loc.T("tray.session.expiresIn", "remaining", remaining))
			t.sessionExpiresItem.SetHidden(false)
		}
	}
	if t.upItem != nil {
		// Connect stays visible in the NeedsLogin states too — Up drives
		// the SSO re-auth flow; hidden only when it would be a no-op.
		t.upItem.SetHidden(connected || connecting || daemonUnavailable)
		t.upItem.SetEnabled(!connected && !connecting && !daemonUnavailable)
	}
	if t.downItem != nil {
		// Disconnect doubles as the Connecting abort path.
		t.downItem.SetHidden(!connected && !connecting)
		t.downItem.SetEnabled(connected || connecting)
	}
	if t.exitNodeItem != nil {
		t.exitNodeItem.SetEnabled(connected && len(exitNodeEntries) > 0 && !disableNetworks)
	}
	if t.settingsItem != nil {
		t.settingsItem.SetEnabled(!daemonUnavailable)
	}
	if t.profileSubmenuItem != nil {
		t.profileSubmenuItem.SetEnabled(!daemonUnavailable && !disableProfiles)
	}
	if daemonVersion != "" && t.daemonVersionItem != nil {
		t.daemonVersionItem.SetLabel(t.loc.T("tray.menu.daemonVersion", "version", daemonVersion))
	}
	if t.updater != nil {
		t.updater.applyLanguage()
	}
	// buildMenu recreated empty submenus, so repaint both from their caches
	// before SetMenu. Neither fill re-fetches. Do NOT re-take
	// exitNodesRebuildMu here — refreshExitNodes already holds it when it
	// calls relayoutMenu.
	t.fillExitNodeSubmenu(exitNodeEntries)
	t.fillProfileSubmenu()

	// Single push of the whole tree: on Linux one LayoutUpdated with fresh
	// container ids; on darwin an NSMenu rebuild against the cached pointer.
	t.tray.SetMenu(t.menu)
}

func (t *Tray) buildMenu() *application.Menu {
	menu := application.NewMenu()

	// Enabled state is platform-dependent (see statusRowEnabled): Windows keeps
	// it enabled because the disabled mask would desaturate the coloured status
	// dot; macOS/Linux disable it so the greyed label signals it isn't
	// clickable.
	t.statusItem = menu.Add(t.loc.T("tray.status.disconnected")).
		SetEnabled(statusRowEnabled()).
		SetBitmap(iconMenuDotIdle)

	menu.AddSeparator()

	// The OnClick closures capture the local item because t.upItem/t.downItem
	// are menuMu-guarded and must not be read from the click goroutine.
	upItem := menu.Add(t.loc.T("tray.menu.connect"))
	upItem.OnClick(func(*application.Context) { t.handleConnect(upItem) })
	t.upItem = upItem
	downItem := menu.Add(t.loc.T("tray.menu.disconnect"))
	downItem.OnClick(func(*application.Context) { t.handleDisconnect(downItem) })
	downItem.SetHidden(true)
	t.downItem = downItem

	menu.AddSeparator()

	// Populated asynchronously once the app has started — Menu.Update() is a
	// no-op before app.running is true, so the initial fill is gated on the
	// ApplicationStarted hook.
	profilesLabel := t.loc.T("tray.menu.profiles")
	t.profileSubmenu = menu.AddSubmenu(profilesLabel)
	// AddSubmenu returns the child *Menu, so retrieve the parent *MenuItem via
	// FindByLabel.
	t.profileSubmenuItem = menu.FindByLabel(profilesLabel)
	t.profileEmailItem = menu.Add("").SetEnabled(false)
	t.profileEmailItem.SetHidden(true)
	// Click opens the SessionExpiration window so the user can extend ahead of
	// the daemon's T-FinalWarningLead auto-prompt.
	t.sessionExpiresItem = menu.Add("").OnClick(func(*application.Context) { t.openSessionExtendFlow() })
	t.sessionExpiresItem.SetHidden(true)

	menu.AddSeparator()
	// Accelerators on the Settings/Quit entries below are a no-op on Windows in
	// Wails v3 alpha.95 (impl commented out in menuitem_windows.go); still set
	// for forward compatibility. macOS/GTK render and fire them.
	menu.Add(t.loc.T("tray.menu.open")).OnClick(func(*application.Context) { t.ShowWindow() })

	menu.AddSeparator()

	// exitNodeSubmenu hosts one row per peer advertising a default route
	// (0.0.0.0/0 or ::/0). FindByLabel grabs the parent so applyStatus can flip
	// its enabled state independently of the children.
	exitNodeLabel := t.loc.T("tray.menu.exitNode")
	t.exitNodeSubmenu = menu.AddSubmenu(exitNodeLabel)
	t.exitNodeItem = menu.FindByLabel(exitNodeLabel)
	t.exitNodeItem.SetEnabled(false)

	menu.AddSeparator()

	// The label's trailing ellipsis follows the macOS HIG convention for items
	// that open a window.
	t.settingsItem = menu.Add(t.loc.T("tray.menu.settings")).
		SetAccelerator("CmdOrCtrl+,").
		OnClick(func(*application.Context) { t.svc.WindowManager.OpenSettings("") })

	aboutLabel := menuLabel(t.loc.T("tray.menu.about"))
	about := menu.AddSubmenu(aboutLabel)
	about.Add(t.loc.T("tray.menu.github")).OnClick(func(*application.Context) {
		_ = t.app.Browser.OpenURL(urlGitHubRepo)
	})
	about.Add(t.loc.T("tray.menu.documentation")).OnClick(func(*application.Context) {
		_ = t.app.Browser.OpenURL(urlDocs)
	})
	about.Add(t.loc.T("tray.menu.troubleshoot")).OnClick(func(*application.Context) {
		t.svc.WindowManager.OpenSettings("troubleshooting")
	})
	about.AddSeparator()
	about.Add(t.loc.T("tray.menu.guiVersion", "version", version.NetbirdVersion())).SetEnabled(false)
	t.daemonVersionItem = about.Add(t.loc.T("tray.menu.daemonVersion", "version", t.loc.T("tray.menu.versionUnknown"))).SetEnabled(false)
	// trayUpdater rewrites the label between downloadLatest (opt-in) and
	// installVersion (enforced) and drives the click.
	updateItem := about.Add(t.loc.T("tray.menu.downloadLatest")).
		OnClick(func(*application.Context) { t.updater.handleClick() })
	updateItem.SetHidden(true)
	t.updater.attach(updateItem)

	menu.AddSeparator()
	menu.Add(t.loc.T("tray.menu.quit")).
		SetAccelerator("CmdOrCtrl+Q").
		OnClick(func(*application.Context) { t.app.Quit() })

	return menu
}

// handleConnect receives the clicked item from the buildMenu closure —
// t.upItem is menuMu-guarded and must not be read here.
func (t *Tray) handleConnect(upItem *application.MenuItem) {
	// NeedsLogin/SessionExpired/LoginFailed won't honor a plain Up RPC — they
	// need the Login → WaitSSOLogin → Up sequence. Emit EventTriggerLogin so
	// the React startLogin() (which owns the BrowserLogin popup) drives it;
	// the hidden main webview is alive and subscribed, so only the popup shows.
	t.statusMu.Lock()
	needsLogin := strings.EqualFold(t.lastStatus, services.StatusNeedsLogin) ||
		strings.EqualFold(t.lastStatus, services.StatusSessionExpired) ||
		strings.EqualFold(t.lastStatus, services.StatusLoginFailed)
	t.statusMu.Unlock()
	if needsLogin {
		t.app.Event.Emit(services.EventTriggerLogin)
		return
	}
	upItem.SetEnabled(false)
	// Arm the SSO auto-handoff: Up() is async and the daemon may flip to
	// NeedsLogin on an SSO peer with no cached token. applyStatus consumes the
	// flag on that transition to trigger browser-login without a second Connect
	// click, and clears it on any terminal state.
	t.statusMu.Lock()
	t.pendingConnectLogin = true
	t.statusMu.Unlock()
	go func() {
		if err := t.svc.Connection.Up(context.Background(), services.UpParams{}); err != nil {
			log.Errorf("connect: %v", err)
			t.notifyError(t.loc.T("notify.error.connect"))
			t.statusMu.Lock()
			t.pendingConnectLogin = false
			t.statusMu.Unlock()
			upItem.SetEnabled(true)
		}
	}()
}

// handleDisconnect aborts any in-flight profile switch before sending Down —
// otherwise the switcher's queued Up would reconnect right after, making the
// click a no-op. Also clears Peers' optimistic-Connecting guard so the daemon's
// Idle push paints through instead of being swallowed by the suppression filter.
// Receives the clicked item from the buildMenu closure (see handleConnect).
func (t *Tray) handleDisconnect(downItem *application.MenuItem) {
	downItem.SetEnabled(false)
	t.profileMu.Lock()
	if t.switchCancel != nil {
		t.switchCancel()
		t.switchCancel = nil
	}
	t.profileMu.Unlock()
	t.svc.DaemonFeed.CancelProfileSwitch()
	go func() {
		if err := t.svc.Connection.Down(context.Background()); err != nil {
			log.Errorf("disconnect: %v", err)
			t.notifyError(t.loc.T("notify.error.disconnect"))
			downItem.SetEnabled(true)
		}
	}()
}

// notify wraps the Wails notification service with the tray's standard
// id-prefix scheme and swallows errors (notifications are best-effort).
func (t *Tray) notify(title, body, id string) {
	if t.svc.Notifier == nil {
		return
	}
	_ = safeSendNotification(t.svc.Notifier.SendNotification, title, notifications.NotificationOptions{
		ID:    id,
		Title: title,
		Body:  body,
	})
}

// notifyError fires a generic "Error" notification for tray-driven action
// failures. Each tray click site already logs the underlying error; this
// adds the user-visible toast.
func (t *Tray) notifyError(message string) {
	t.notify(t.loc.T("notify.error.title"), message, notifyIDTrayError)
}
