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

// Translation keys for every user-facing string the tray paints. The text
// itself lives in i18n/locales/<lang>/common.json — both the tray and the
// React UI read from there so a single bundle drives the whole product.
// Keys are referenced by the Tray.tr helper.

// Non-translated identifiers. Notification IDs coalesce duplicate toasts
// (the OS uses them as dedup keys); statusError is a tray-only sentinel
// distinguishing the error-icon state from real daemon status strings;
// URLs are baked-in product links.
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
	Networks        *services.Networks
	DaemonFeed      *services.DaemonFeed
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
	// panelDark reports whether the desktop panel uses a dark colour
	// scheme, so iconForState can pick the black vs white monochrome tray
	// icon on Linux. Set by startTrayTheme (Linux only); nil on macOS and
	// Windows, where the OS/Wails handles light-vs-dark icon selection and
	// panelIsDark falls back to its default.
	panelDark func() bool
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
	exitNodeSubmenu    *application.Menu
	profileSubmenu     *application.Menu
	profileSubmenuItem *application.MenuItem
	profileEmailItem   *application.MenuItem
	settingsItem       *application.MenuItem
	daemonVersionItem  *application.MenuItem

	updater *trayUpdater

	// statusMu guards the daemon-status core mirrored on the tray —
	// connected, the last status string, the daemon version, the
	// routed-networks revision, and the post-connect login-trigger flag.
	// These are all written by applyStatus and read by the menu painters
	// (applyIcon, relayoutMenu, refreshExitNodes' connected sample,
	// etc.). One mutex covers them because they change together on every
	// Status push.
	statusMu          sync.Mutex
	connected         bool
	lastStatus        string
	lastDaemonVersion string
	// lastNetworksRevision is the daemon's routed-networks revision from
	// the last Status snapshot; a bump in it — or a connect/disconnect
	// transition — is what triggers a refreshExitNodes re-fetch, so we
	// hit ListNetworks only when routes or their selection actually
	// change rather than on every push. The peer-status route list can't
	// be used here: it only carries actively-routed (chosen) routes, not
	// candidate exit nodes.
	lastNetworksRevision uint64
	// pendingConnectLogin is set when handleConnect kicks off an Up on
	// an idle daemon. The daemon will flip to NeedsLogin if the peer is
	// SSO-tracked and has no cached token; applyStatus consumes this
	// flag on that transition to automatically open the browser-login
	// flow, saving the user a second Connect click.
	//
	// Profile-switch reconnects (which also fire an Up) are handled
	// centrally by DaemonFeed.statusStreamLoop — see DaemonFeed's
	// switchInProgress transitions and its EventTriggerLogin emit, so
	// that the React UI's profile dropdown gets the same auto-handoff
	// without going through this tray flag.
	pendingConnectLogin bool

	// sessionMu guards the cached SSO deadline used by the "Session: 47m"
	// tray row. Independent of statusMu because the ticker reads it on a
	// 30s cadence and applySessionExpiry writes it whenever the daemon's
	// Status push carries a new value — neither should block the other's
	// readers.
	sessionMu sync.Mutex
	// sessionExpiresAt is the most recent deadline observed on a Status
	// snapshot. Used to skip a no-op label rewrite when the daemon
	// repeats the same value across rapid pushes.
	sessionExpiresAt time.Time

	// profileMu guards the profile-domain state: the active profile
	// identity cached by loadConfig, the notifications gate also cached
	// there, and the in-flight switchProfile cancel. Independent of
	// statusMu because a long-running switch (Down + Up) holds the
	// switchCancel write under this lock, and we don't want it to block
	// a concurrent Status-push reader of t.connected.
	profileMu            sync.Mutex
	activeProfile        string
	activeUsername       string
	notificationsEnabled bool
	switchCancel         context.CancelFunc

	// profileLoadMu serializes loadProfiles so the daemon-status-driven
	// refresh in applyStatus cannot race with the ApplicationStarted seed
	// or the post-switchProfile reload — both manipulate profileSubmenu and
	// SetMenu, which the Wails menu API is not safe against concurrent
	// callers.
	profileLoadMu sync.Mutex

	// profilesMu guards the cached profile rows that relayoutMenu repaints
	// into a freshly built Profiles submenu. loadProfiles fetches and stores
	// them here; fillProfileSubmenu reads them. Kept separate from the live
	// submenu so a relayout (which throws the old submenu away) always has a
	// source of truth to repaint from without re-hitting the daemon.
	profilesMu   sync.Mutex
	profiles     []services.Profile
	profilesUser string

	// menuMu serialises relayoutMenu — the full buildMenu + SetMenu cycle.
	// loadProfiles (under profileLoadMu) and refreshExitNodes (under
	// exitNodesRebuildMu) both drive a relayout from independent mutexes, and
	// applyLanguage drives one from the Localizer goroutine; without this guard
	// two relayouts could interleave their t.menu swap and SetMenu push.
	menuMu sync.Mutex

	// exitNodesMu guards the t.exitNodes row cache so reading the cached
	// rows in relayoutMenu (and tearing a copy off the slice for
	// Repaint) doesn't contend with status-push readers of statusMu.
	exitNodesMu sync.Mutex
	// exitNodes are the rows currently painted into the Exit Node
	// submenu, sourced from Networks.List() (NetID + selected state) so
	// each row can be toggled.
	exitNodes []exitNodeEntry
	// exitNodesRebuildMu serialises the submenu.Clear + Add + SetMenu
	// cycle. The Status stream can fire several pushes in quick
	// succession and each may kick a refresh, but the ListNetworks fetch +
	// submenu rebuild + SetMenu must not run concurrently with itself.
	exitNodesRebuildMu sync.Mutex

	// featureMu guards the daemon feature kill switches mirrored on the
	// tray. Fetched once at startup and refreshed on every config_changed
	// system event (the daemon re-applies MDM policy on each engine spawn
	// and signals it via that event). Folded into the Profiles and Exit
	// Node menu enablement by featuresDisabled so an operator- or
	// MDM-disabled surface greys out without a periodic GetFeatures poll.
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
		// Localizer is constructed by main from the i18n.Bundle and
		// preferences.Store so the first menu render below is already in
		// the right locale — no English flash followed by a re-paint.
		loc: svc.Localizer,
	}
	t.updater = newTrayUpdater(app, window, svc.Update, svc.Notifier, t.loc, func() { t.applyIcon() }, func() { t.relayoutMenu() })
	t.tray = app.SystemTray.New()
	// Seed panel-theme detection (Linux only) before the first paint so the
	// initial icon already matches the panel's light/dark scheme; repaints
	// on live theme switches.
	t.startTrayTheme()
	t.applyIcon()
	t.tray.SetTooltip(t.loc.T("tray.tooltip"))
	// On Linux the SNI hover tooltip is sourced from the systray *Label*
	// (the StatusNotifierItem Title/ToolTip props), not SetTooltip —
	// SetTooltip is a no-op on Linux. With no label set, Wails falls back
	// to the literal "Wails", so set it explicitly here. macOS is skipped
	// because its setLabel paints visible text next to the icon; Windows
	// is skipped because its tooltip comes from SetTooltip above.
	if runtime.GOOS == "linux" {
		t.tray.SetLabel(t.loc.T("tray.tooltip"))
	}
	t.menu = t.buildMenu()
	t.tray.SetMenu(t.menu)
	// Left-click on the tray icon opens the menu, and the window is reached
	// through the explicit "Open NetBird" entry. This matches macOS
	// NSStatusItem convention (click → menu), the Linux StatusNotifierItem
	// spec, and the legacy Fyne client. macOS and Linux give us click→menu
	// natively, so bindTrayClick is a no-op there (binding OnClick→OpenMenu
	// on macOS would freeze the tray — see tray_click_other.go). Windows has
	// no native left-click handler, so bindTrayClick wires one explicitly
	// (see tray_click_windows.go). On Linux we deliberately skip AttachWindow:
	// it plus Wails3's applySmartDefaults would pop the window alongside the
	// menu on environments like GNOME Shell with the AppIndicator extension.
	// Right-click opens the menu through Wails' default rightClickHandler on
	// every platform.
	bindTrayClick(t)

	app.Event.On(services.EventStatusSnapshot, t.onStatusEvent)
	app.Event.On(services.EventDaemonNotification, t.onSystemEvent)
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
		// Seed the feature kill switches so a DisableProfiles / DisableNetworks
		// policy already greys out the matching menus on the first paint
		// (config_changed events refresh them afterwards).
		go t.refreshFeatures()
		go t.runSessionExpiryTicker()
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

// ShowWindow brings the main window forward — used by SIGUSR1 / Windows event.
// Show() alone is not enough on macOS: makeKeyAndOrderFront skips app
// activation, so a tray-style app's window pops up behind the currently
// active app. Focus() additionally calls activateIgnoringOtherApps:YES on
// macOS and SetForegroundWindow on Windows.
func (t *Tray) ShowWindow() {
	// While an auto-update install is running the install-progress window
	// is the focal surface (all other windows hidden by WindowManager).
	// Tray "Open" / SIGUSR1 / dock-reopen should bring it forward, not
	// resurrect the main one mid-install. Checked before BrowserLogin
	// because an install supersedes every other flow.
	if w := t.svc.WindowManager.InstallProgressWindow(); w != nil {
		w.Show()
		w.Focus()
		return
	}
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
	// Route through WindowManager so the main window is centered on its
	// first show (see WindowManager.ShowMain) — minimal WMs (fluxbox, the
	// XEmbed tray path) otherwise drop it in the top-left corner.
	if t.svc.WindowManager != nil {
		t.svc.WindowManager.ShowMain()
		return
	}
	t.window.Show()
	t.window.Focus()
}

// applyLanguage re-renders every translated surface using the Localizer's
// current language. Wails dispatches menu/tray APIs onto the platform's
// UI thread internally, so calling them from the Localizer's background
// goroutine is safe; profileLoadMu prevents loadProfiles from racing the
// rebuild.
func (t *Tray) applyLanguage() {
	t.tray.SetTooltip(t.loc.T("tray.tooltip"))
	// Mirror the Linux label fix from NewTray — the SNI hover tooltip
	// rides on the label, so refresh it on language change too.
	if runtime.GOOS == "linux" {
		t.tray.SetLabel(t.loc.T("tray.tooltip"))
	}
	t.relayoutMenu()
}

// relayoutMenu rebuilds the ENTIRE tray menu from scratch (buildMenu), repaints
// the cached status/session/profile/exit-node state into the fresh items, and
// pushes the whole tree with a single SetMenu. It is the only Linux path that
// reliably propagates submenu changes.
//
// Why a full rebuild rather than mutating the existing submenu in place: on
// KDE/Plasma the StatusNotifierItem host caches a submenu's layout the first
// time it is opened (GetLayout for that submenu id) and never re-fetches it on
// a LayoutUpdated(parent=0) signal — so Clear()+Add() into the same submenu
// container left the visible menu (and, worse, the click→id mapping) frozen on
// the first snapshot: clicks sent the stale ids, which the freshly-rebuilt
// itemMap no longer knew, so they silently no-op'd. buildMenu allocates a brand
// new submenu container id every time, which Plasma treats as an unseen menu
// and re-queries on next open — both the labels and the click ids stay live.
// (Confirmed via dbus-monitor: a re-opened submenu issued no GetLayout until
// its container id changed.) The darwin detached-NSMenu workaround that the old
// per-submenu SetMenu addressed is also covered, since this rebuilds the whole
// tree against the cached top-level pointer.
//
// Pulls profile/exit-node rows from their caches (profilesMu / exitNodes) so it
// never re-hits the daemon and never recurses back into loadProfiles.
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
		t.upItem.SetHidden(connected || connecting || daemonUnavailable)
		t.upItem.SetEnabled(!connected && !connecting && !daemonUnavailable)
	}
	if t.downItem != nil {
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
	// buildMenu just recreated empty Profiles + Exit Node submenus, so repaint
	// both from their caches before the single SetMenu below. fillExitNodeSubmenu
	// uses the entries snapshotted above; fillProfileSubmenu reads profilesMu.
	// Neither re-fetches, so relayoutMenu never recurses back into
	// loadProfiles/refreshExitNodes. (We must NOT re-take exitNodesRebuildMu
	// here — refreshExitNodes already holds it when it calls relayoutMenu.)
	t.fillExitNodeSubmenu(exitNodeEntries)
	t.fillProfileSubmenu()

	// Single push of the whole tree. On Linux this emits one LayoutUpdated with
	// fresh submenu container ids; on darwin it rebuilds the NSMenu against the
	// cached top-level pointer.
	t.tray.SetMenu(t.menu)
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

	menu.AddSeparator()

	// Only the action that applies to the current state is visible: Connect
	// when disconnected, Disconnect when connected. applyStatus swaps them on
	// each daemon status change.
	t.upItem = menu.Add(t.loc.T("tray.menu.connect")).OnClick(func(*application.Context) { t.handleConnect() })
	t.downItem = menu.Add(t.loc.T("tray.menu.disconnect")).OnClick(func(*application.Context) { t.handleDisconnect() })
	t.downItem.SetHidden(true)

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
	// sessionExpiresItem sits below the profile email so the active profile,
	// its account email, and the SSO session deadline read as a single block.
	// Hidden until applyStatus sees a non-zero SessionExpiresAt on the daemon
	// Status snapshot — peers without SSO tracking or with login expiry
	// disabled never reveal this row. Click opens the SessionExpiration
	// window so the user can extend the session ahead of the daemon's
	// T-FinalWarningLead auto-prompt.
	t.sessionExpiresItem = menu.Add("").OnClick(func(*application.Context) { t.openSessionExtendFlow() })
	t.sessionExpiresItem.SetHidden(true)

	menu.AddSeparator()
	// The tray icon's left-click handler is intentionally unbound (see
	// NewTray for the rationale), so expose the window through an explicit
	// menu entry on every platform.
	//
	// Accelerators are wired on the Settings and Quit entries below.
	// Cross-platform behaviour in Wails v3 alpha.95:
	//   - macOS: SetAccelerator calls NSMenuItem.setKeyEquivalent — the
	//     glyph row paints to the right of the label and the combo fires
	//     when the menu is open OR while the app is the frontmost app.
	//   - Linux (GTK): SetAccelerator binds the GTK accel — the combo
	//     fires while the menu is open and the label paints the row. On
	//     XEmbed/AppIndicator hosts the visual hint may not render but
	//     activation through the keyboard still resolves.
	//   - Windows: SetAccelerator is a no-op in alpha.95 (the impl is
	//     commented out in menuitem_windows.go), so the row is plain
	//     text. We still call it for forward compatibility — a future
	//     Wails release picks the labels up without churn here.
	menu.Add(t.loc.T("tray.menu.open")).OnClick(func(*application.Context) { t.ShowWindow() })

	menu.AddSeparator()

	// exitNodeSubmenu hosts one row per peer advertising a default
	// route (0.0.0.0/0 or ::/0). Populated asynchronously by
	// refreshExitNodes (via relayoutMenu) on every Status push that changes the set;
	// the parent row stays disabled until at least one candidate is
	// known. We grab the parent MenuItem via FindByLabel (same
	// pattern as the Profiles submenu) so applyStatus can flip its
	// enabled state independently of the children.
	exitNodeLabel := t.loc.T("tray.menu.exitNode")
	t.exitNodeSubmenu = menu.AddSubmenu(exitNodeLabel)
	t.exitNodeItem = menu.FindByLabel(exitNodeLabel)
	t.exitNodeItem.SetEnabled(false)

	menu.AddSeparator()

	// Settings, runtime toggles (SSH, Quantum-Resistance, lazy connection,
	// block-inbound, auto-connect, notifications) and profile switching
	// all live in the in-window Settings page now. The tray menu only
	// surfaces the day-to-day actions. The trailing ellipsis on the label
	// (i18n string) follows the macOS HIG convention for menu items that
	// open a dialog/window rather than performing an inline action.
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
	// Troubleshoot deep-links into the Settings window at the
	// Troubleshooting tab, which hosts the debug-bundle flow that used
	// to live as a top-level tray entry.
	about.Add(t.loc.T("tray.menu.troubleshoot")).OnClick(func(*application.Context) {
		t.svc.WindowManager.OpenSettings("troubleshooting")
	})
	about.AddSeparator()
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
	menu.Add(t.loc.T("tray.menu.quit")).
		SetAccelerator("CmdOrCtrl+Q").
		OnClick(func(*application.Context) { t.app.Quit() })

	return menu
}

func (t *Tray) handleConnect() {
	// NeedsLogin/SessionExpired/LoginFailed mean the daemon won't honor a
	// plain Up RPC ("up already in progress: current status NeedsLogin") —
	// it needs the Login → WaitSSOLogin → Up sequence instead. Emit
	// EventTriggerLogin so the React-side startLogin() (which owns the
	// BrowserLogin popup) drives the flow. The main window's webview is
	// alive even while hidden, so we don't surface it — only the popup
	// appears.
	t.statusMu.Lock()
	needsLogin := strings.EqualFold(t.lastStatus, services.StatusNeedsLogin) ||
		strings.EqualFold(t.lastStatus, services.StatusSessionExpired) ||
		strings.EqualFold(t.lastStatus, services.StatusLoginFailed)
	t.statusMu.Unlock()
	if needsLogin {
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
			t.downItem.SetEnabled(true)
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
