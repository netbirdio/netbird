//go:build !android && !ios && !freebsd && !js

package main

import (
	"context"
	"embed"
	"flag"
	"io/fs"
	"log"
	"runtime"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
	"github.com/wailsapp/wails/v3/pkg/services/notifications"

	"github.com/netbirdio/netbird/client/ui/authsession"
	"github.com/netbirdio/netbird/client/ui/i18n"
	"github.com/netbirdio/netbird/client/ui/preferences"
	"github.com/netbirdio/netbird/client/ui/services"
	"github.com/netbirdio/netbird/client/ui/updater"
	"github.com/netbirdio/netbird/util"
)

//go:embed all:frontend/dist
var assets embed.FS

// localesRoot embeds the i18n bundles shared by the tray (Go) and the React
// UI (Vite imports the same files). The `all:` prefix is required so
// _index.json is included — //go:embed drops files starting with "_" or "."
// otherwise.
//
//go:embed all:i18n/locales
var localesRoot embed.FS

// stringList collects repeated string flags. The first user-supplied value
// drops the seeded default; subsequent passes append.
type stringList struct {
	values  []string
	userSet bool
}

func (s *stringList) String() string {
	return strings.Join(s.values, ",")
}

func (s *stringList) Set(v string) error {
	if !s.userSet {
		s.values = nil
		s.userSet = true
	}
	s.values = append(s.values, v)
	return nil
}

type registeredServices struct {
	connection      *services.Connection
	authSession     *authsession.Session
	settings        *services.Settings
	networks        *services.Networks
	profiles        *services.Profiles
	update          *services.Update
	daemonFeed      *services.DaemonFeed
	notifier        *notifications.NotificationService
	compat          *services.Compat
	profileSwitcher *services.ProfileSwitcher
	bundle          *i18n.Bundle
	prefStore       *preferences.Store
}

func init() {
	application.RegisterEvent[services.Status](services.EventStatusSnapshot)
	application.RegisterEvent[services.SystemEvent](services.EventDaemonNotification)
	application.RegisterEvent[services.ProfileRef](services.EventProfileChanged)
	application.RegisterEvent[authsession.Warning](services.EventSessionWarning)
	application.RegisterEvent[updater.State](updater.EventStateChanged)
	application.RegisterEvent[preferences.UIPreferences](preferences.EventPreferencesChanged)
}

func main() {
	daemonAddr, userSetLogFile := parseFlagsAndInitLog()
	conn := NewConn(daemonAddr)

	// Without --log-file, the GUI manages a gui-client.log that follows the
	// daemon's debug level and is collected in the debug bundle. It rides
	// DaemonFeed's SubscribeEvents stream (see guilog.DebugLog).
	debugLog := newDebugLog(userSetLogFile)

	// Declared before app.New so the SingleInstance callback closes over it.
	var tray *Tray
	app := newApplication(func() {
		if tray != nil {
			tray.ShowWindow()
		}
	})

	settings := services.NewSettings(conn)
	profiles := services.NewProfiles(conn)
	// updater.Holder owns the typed update State; DaemonFeed feeds it and the
	// Update service is a thin Wails-bound facade over it plus the install RPCs.
	updaterHolder := updater.NewHolder(app.Event)
	update := services.NewUpdate(conn, updaterHolder)
	daemonFeed := services.NewDaemonFeed(conn, app.Event, updaterHolder, debugLog)
	notifier := notifications.New()
	compat := services.NewCompat(conn)
	// macOS shows no toast until permission is requested. Run it after
	// ApplicationStarted so the notifier's Startup has initialised the
	// notification-center delegate. No-op on Linux/Windows (stubs report
	// authorized).
	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		go requestNotificationAuthorization(notifier)
		initDockObserver()
	})

	bundle, prefStore, localizer := buildI18n(app)

	// After bundle + prefStore: both are used to localise daemon errors.
	connection := services.NewConnection(conn, bundle, prefStore)
	profileSwitcher := services.NewProfileSwitcher(profiles, connection, daemonFeed)
	// authsession.Session owns the full extend + dismiss surface the tray
	// drives directly; the Wails-bound services.Session wraps only the subset
	// the React frontend calls, keeping the generated TS surface minimal.
	authSession := authsession.NewSession(conn)
	networks := services.NewNetworks(conn)

	registerServices(app, conn, registeredServices{
		connection:      connection,
		authSession:     authSession,
		settings:        settings,
		networks:        networks,
		profiles:        profiles,
		update:          update,
		daemonFeed:      daemonFeed,
		notifier:        notifier,
		compat:          compat,
		profileSwitcher: profileSwitcher,
		bundle:          bundle,
		prefStore:       prefStore,
	})

	window := newMainWindow(app, prefStore)

	// Settings is created eagerly (hidden) so the first gear click paints
	// instantly and React keeps per-tab state across reopens. The other
	// auxiliary windows stay lazy + destroy-on-close so Wails's macOS
	// dock-reopen handler can't resurrect them.
	windowManager := services.NewWindowManager(app, window, bundle, prefStore, iconWindow)
	// Minimal WMs (XEmbed-tray path) neither center small windows nor restore
	// position across hide -> show, dropping them top-left. Gate Go-side
	// re-centering on that environment; nil leaves placement to the WM on full
	// desktops, macOS, and Windows.
	windowManager.SetRecenterOnShow(recenterOnShowPredicate())
	app.RegisterService(application.NewService(windowManager))

	// Welcome window, first launch only — Continue flips OnboardingCompleted
	// so later launches skip it. ApplicationStarted hook so the Wails window
	// machinery is fully up before the window is created.
	if !prefStore.Get().OnboardingCompleted {
		app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
			windowManager.OpenWelcome()
		})
	}

	// In-process StatusNotifierWatcher so the tray works on minimal WMs that
	// don't ship one (Fluxbox, i3, GNOME without AppIndicator). No-op off
	// Linux. Must run before NewTray so the systray's
	// RegisterStatusNotifierItem hits a watcher we control.
	startStatusNotifierWatcher()

	tray = NewTray(app, window, TrayServices{
		Connection:      connection,
		Settings:        settings,
		Profiles:        profiles,
		Networks:        networks,
		DaemonFeed:      daemonFeed,
		Notifier:        notifier,
		Update:          update,
		ProfileSwitcher: profileSwitcher,
		WindowManager:   windowManager,
		Session:         authSession,
		Localizer:       localizer,
	})
	listenForShowSignal(context.Background(), tray)

	// Start the feed only after every service's ServiceStartup has run. The
	// first SubscribeEvents message replays cached state synchronously and can
	// fire an OS notification; if Watch ran before app.Run it could beat the
	// notifier's ServiceStartup, where the Linux notifier connects the session
	// bus — its *dbus.Conn would still be nil and SendNotification would
	// nil-deref (fatal panic on the dispatch goroutine, observed on Linux
	// Mint). ApplicationStarted fires after the startup loop, so the bus is up.
	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		daemonFeed.Watch(context.Background())
		// Probe daemon compatibility once the notifier bus is up; an outdated
		// daemon may keep the main window from showing, so the OS toast is the
		// only reliable signal the user gets.
		go notifyIfDaemonOutdated(compat, notifier, localizer)
		// One-time launch-on-login default for fresh installs; gated by the
		// NetBird footprint check, MDM policy, and the persisted marker.
		go applyAutostartDefault(context.Background(), services.NewAutostart(app.Autostart), prefStore, prefStore.ExistedAtLoad())
	})

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}

// requestNotificationAuthorization prompts for macOS notification permission.
// The request blocks until the user responds (up to 3 minutes), so callers run
// it in a goroutine. No-op on Linux/Windows.
func requestNotificationAuthorization(notifier *notifications.NotificationService) {
	authorized, err := notifier.CheckNotificationAuthorization()
	if err != nil {
		logrus.Debugf("check notification authorization: %v", err)
		return
	}
	if authorized {
		return
	}
	if _, err := notifier.RequestNotificationAuthorization(); err != nil {
		logrus.Debugf("request notification authorization: %v", err)
	}
}

// parseFlagsAndInitLog returns the daemon gRPC address and userSetLogFile
// (true when --log-file was passed). userSetLogFile is the manual-override
// signal: true leaves logging alone, false lets the GUI manage a
// daemon-driven gui-client.log. The flag default is empty (not "console") so
// "no flag" and an explicit "--log-file console" stay distinguishable; empty
// falls back to console for InitLog.
func parseFlagsAndInitLog() (string, bool) {
	daemonAddr := flag.String("daemon-addr", DaemonAddr(), "Daemon gRPC address: unix:///path or tcp://host:port")
	logFiles := &stringList{}
	flag.Var(logFiles, "log-file", "Log destination. Repeat to log to multiple targets at once, e.g. `--log-file console --log-file Y:/netbird-ui.log`. Each value is one of: console, syslog, or a file path. File destinations are rotated by lumberjack (same as the daemon). Defaults to console. Passing any value disables the daemon-debug-driven gui-client.log.")
	logLevel := flag.String("log-level", "info", "Log level: trace|debug|info|warn|error.")
	flag.Parse()

	userSetLogFile := len(logFiles.values) > 0
	targets := logFiles.values
	if !userSetLogFile {
		targets = []string{"console"}
	}

	if err := util.InitLog(*logLevel, targets...); err != nil {
		log.Fatalf("init log: %v", err)
	}
	return *daemonAddr, userSetLogFile
}

// newApplication constructs the Wails application. onSecondInstance fires when
// a second process launches under the same SingleInstance UniqueID.
func newApplication(onSecondInstance func()) *application.App {
	// On macOS, Options.Icon feeds NSApplication's setApplicationIconImage,
	// overriding the bundle icon (Assets.car / icons.icns) the OS already
	// picked. Suppress it on darwin to keep the bundle's squircle.
	appIcon := iconWindow
	if runtime.GOOS == "darwin" {
		appIcon = nil
	}

	return application.New(application.Options{
		// On Windows, Name is the AppUserModelID for toast notifications and
		// the HKCU\Software\Classes\AppUserModelId\ registry path. It must
		// match the System.AppUserModel.ID the MSI sets on the Start Menu
		// shortcut (client/netbird.wxs) and the AppUserModelId key the
		// installer pre-populates with the toast activator CLSID; otherwise
		// toasts show under a different identity and the MSI's CustomActivator
		// value is orphaned.
		Name:        "NetBird",
		Description: "NetBird desktop client",
		Icon:        appIcon,
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: false,
			ActivationPolicy: application.ActivationPolicyAccessory,
		},
		Linux: application.LinuxOptions{
			ProgramName: "netbird",
		},
		SingleInstance: &application.SingleInstanceOptions{
			UniqueID: "io.netbird.ui",
			OnSecondInstanceLaunch: func(_ application.SecondInstanceData) {
				onSecondInstance()
			},
		},
	})
}

// buildI18n constructs the i18n bundle, preferences store, and tray localizer.
// The Bundle satisfies preferences.LanguageValidator so SetLanguage rejects
// codes that have no shipped translation.
func buildI18n(app *application.App) (*i18n.Bundle, *preferences.Store, *Localizer) {
	// Reroot the embedded tree at the locales dir so the bundle sees
	// _index.json and <lang>/common.json at top level (//go:embed roots at
	// the package, not the leaf dir).
	localesFS, err := fs.Sub(localesRoot, "i18n/locales")
	if err != nil {
		log.Fatalf("locate locales fs: %v", err)
	}
	bundle, err := i18n.NewBundle(localesFS)
	if err != nil {
		log.Fatalf("init i18n bundle: %v", err)
	}
	prefStore, err := preferences.NewStore(bundle, app.Event)
	if err != nil {
		log.Fatalf("init preferences store: %v", err)
	}
	return bundle, prefStore, NewLocalizer(bundle, prefStore)
}

// registerServices binds every Wails-facing service onto the application.
// Services with no other caller are constructed inline; the rest arrive
// already built so the tray and feed loops share the same instances.
func registerServices(app *application.App, conn *Conn, s registeredServices) {
	app.RegisterService(application.NewService(s.connection))
	app.RegisterService(application.NewService(services.NewSession(s.authSession, s.bundle, s.prefStore)))
	app.RegisterService(application.NewService(s.settings))
	app.RegisterService(application.NewService(s.networks))
	app.RegisterService(application.NewService(services.NewForwarding(conn)))
	app.RegisterService(application.NewService(s.profiles))
	app.RegisterService(application.NewService(services.NewDebug(conn)))
	app.RegisterService(application.NewService(s.update))
	app.RegisterService(application.NewService(s.daemonFeed))
	app.RegisterService(application.NewService(s.notifier))
	app.RegisterService(application.NewService(s.profileSwitcher))
	app.RegisterService(application.NewService(services.NewI18n(s.bundle)))
	app.RegisterService(application.NewService(services.NewPreferences(s.prefStore)))
	app.RegisterService(application.NewService(services.NewAutostart(app.Autostart)))
	app.RegisterService(application.NewService(services.NewVersion()))
	app.RegisterService(application.NewService(services.NewUILog()))
	app.RegisterService(application.NewService(s.compat))
}

// newMainWindow creates the hidden main window, sized to the user's last view
// mode, and installs the hide-on-close and macOS dock-reopen hooks.
func newMainWindow(app *application.App, prefStore *preferences.Store) *application.WebviewWindow {
	// Width matches the last view mode so Advanced-mode users don't see the
	// window pop from 380px to 900px on launch. Height is mode-agnostic.
	initialWidth := 380
	if prefStore.Get().ViewMode == preferences.ViewModeAdvanced {
		initialWidth = 900
	}
	window := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Name:   "main",
		Title:  "NetBird",
		Width:  initialWidth,
		Height: services.WindowHeight,
		// Center on first show; minimal WMs (fluxbox, the XEmbed tray path)
		// drop new windows top-left unless asked.
		InitialPosition:     application.WindowCentered,
		Hidden:              true,
		BackgroundColour:    services.WindowBackgroundColour,
		URL:                 "/",
		DisableResize:       true,
		MinimiseButtonState: application.ButtonHidden,
		MaximiseButtonState: application.ButtonHidden,
		Mac:                 services.AppleMacOSAppearanceOptions(),
		Windows:             services.MicrosoftWindowsAppearanceOptions(),
		Linux: application.LinuxWindow{
			Icon: iconWindow,
		},
	})

	// Hide instead of quit on close; "really quit" is reached via tray -> Quit.
	window.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		e.Cancel()
		window.Hide()
	})

	// On macOS, Wails' default applicationShouldHandleReopen handler Show()s
	// every hidden window on dock-icon click, resurrecting hide-on-close
	// surfaces like Settings. Cancel it in a hook (hooks run before listeners)
	// and show only the main window. No-op elsewhere — the event never fires.
	if runtime.GOOS == "darwin" {
		app.Event.RegisterApplicationEventHook(events.Mac.ApplicationShouldHandleReopen, func(e *application.ApplicationEvent) {
			e.Cancel()
			if e.Context().HasVisibleWindows() {
				return
			}
			window.Show()
			window.Focus()
		})
	}

	return window
}
