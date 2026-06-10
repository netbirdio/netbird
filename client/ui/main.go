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

// localesFS roots the i18n translation bundles. Embedded from the same
// directory the React app imports, so a single JSON source drives both
// the tray (Go) and the in-window UI (Vite imports the files directly).
// The `all:` prefix is required so _index.json is included — //go:embed
// silently drops files whose names start with "_" or "." otherwise.
//
//go:embed all:i18n/locales
var localesRoot embed.FS

// stringList is a flag.Value that collects repeated string flags. The first
// time the user passes -log-file the seeded default ("console") is dropped;
// subsequent passes append. Lets the user replace or extend the log target
// list without a separate "reset" flag.
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

// registeredServices bundles the constructed services that registerServices
// binds to the Wails app, keeping the call site readable.
type registeredServices struct {
	connection      *services.Connection
	authSession     *authsession.Session
	settings        *services.Settings
	networks        *services.Networks
	profiles        *services.Profiles
	update          *services.Update
	daemonFeed      *services.DaemonFeed
	notifier        *notifications.NotificationService
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
	daemonAddr := parseFlagsAndInitLog()
	conn := NewConn(daemonAddr)

	// tray is captured in the SingleInstance callback below; the var is
	// declared before app.New so the closure has a stable reference.
	var tray *Tray
	app := newApplication(func() {
		if tray != nil {
			tray.ShowWindow()
		}
	})

	settings := services.NewSettings(conn)
	profiles := services.NewProfiles(conn)
	// updater.Holder owns the typed update State. DaemonFeed pipes the
	// daemon SubscribeEvents stream into it; the Update service is a thin
	// Wails-bound facade over the holder plus the install RPCs.
	updaterHolder := updater.NewHolder(app.Event)
	update := services.NewUpdate(conn, updaterHolder)
	daemonFeed := services.NewDaemonFeed(conn, app.Event, updaterHolder)
	notifier := notifications.New()
	// macOS won't surface any toast until the app has requested permission;
	// the request runs after ApplicationStarted so the notifier's Startup has
	// initialised the notification-center delegate. Linux/Windows stubs return
	// authorized, so this is a no-op there.
	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		go requestNotificationAuthorization(notifier)
	})

	bundle, prefStore, localizer := buildI18n(app)

	// Connection lives after bundle + prefStore so it can localise daemon
	// errors (services.NewConnection takes both as dependencies).
	connection := services.NewConnection(conn, bundle, prefStore)
	profileSwitcher := services.NewProfileSwitcher(profiles, connection, daemonFeed)
	// authsession.Session owns the full extend + dismiss surface; the tray
	// drives the "Extend now" action from the T-10 OS notification through
	// this directly. The Wails-bound services.Session wraps only the subset
	// the React frontend calls, so the generated TS surface stays minimal.
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
		profileSwitcher: profileSwitcher,
		bundle:          bundle,
		prefStore:       prefStore,
	})

	window := newMainWindow(app, prefStore)

	// Settings is created eagerly (hidden) inside NewWindowManager so the
	// first click on the gear paints instantly and the React side keeps
	// per-tab state across reopens. The other auxiliary windows
	// (BrowserLogin, Session*, InstallProgress) stay lazy + destroy-on-close
	// so they don't linger as hidden windows that Wails's macOS dock-reopen
	// handler would pop back up.
	windowManager := services.NewWindowManager(app, window, bundle, prefStore, iconWindow)
	// On minimal WMs (the in-process XEmbed-tray path) the WM neither centers
	// small windows nor restores their position across a hide -> show, so the
	// main/Settings windows would open in the top-left corner. Gate Go-side
	// re-centering on that environment; nil (full desktops, macOS, Windows)
	// leaves placement to the WM. See WindowManager.SetRecenterOnShow.
	windowManager.SetRecenterOnShow(recenterOnShowPredicate())
	app.RegisterService(application.NewService(windowManager))

	// Welcome / onboarding window. First launch only — the Continue
	// button in the dialog flips OnboardingCompleted=true via the
	// Preferences service before closing, so subsequent launches skip
	// straight to the tray-only flow. ApplicationStarted hook so the
	// Wails window machinery is fully up before the window is created.
	if !prefStore.Get().OnboardingCompleted {
		app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
			windowManager.OpenWelcome()
		})
	}

	// Register an in-process StatusNotifierWatcher so the tray works on
	// minimal WMs (Fluxbox, OpenBox, i3, dwm, vanilla GNOME without the
	// AppIndicator extension) that don't ship one themselves. No-op on
	// non-Linux platforms. Must run before NewTray so the Wails systray's
	// RegisterStatusNotifierItem call hits a watcher we control.
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

	// Start the daemon event feed only after Wails has run every service's
	// ServiceStartup. The very first daemon SubscribeEvents message replays
	// the cached state (status + available update) synchronously, which fans
	// out through app.Event into the tray's update-state listener and fires an
	// OS notification. If Watch ran before app.Run, that send could beat the
	// notifications service's ServiceStartup — on Linux the Wails notifier
	// connects to the session bus there, so its *dbus.Conn would still be nil
	// and SendNotification would nil-deref (fatal panic on the event-dispatch
	// goroutine; observed on Linux Mint). ApplicationStarted fires inside
	// app.Run after the synchronous service-startup loop, so the bus is up by
	// the time the first event lands.
	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		daemonFeed.Watch(context.Background())
	})

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}

// requestNotificationAuthorization prompts for macOS notification permission
// when the app first runs unauthorized. RequestNotificationAuthorization
// blocks until the user responds (up to 3 minutes on macOS), so callers run
// it in a goroutine. On Linux/Windows the Wails notifier stubs report
// authorized, making this a no-op.
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

// parseFlagsAndInitLog parses the CLI flags, initialises the logger, and
// returns the resolved daemon gRPC address.
func parseFlagsAndInitLog() string {
	daemonAddr := flag.String("daemon-addr", DaemonAddr(), "Daemon gRPC address: unix:///path or tcp://host:port")
	logFiles := &stringList{values: []string{"console"}}
	flag.Var(logFiles, "log-file", "Log destination. Repeat to log to multiple targets at once, e.g. `--log-file console --log-file Y:/netbird-ui.log`. Each value is one of: console, syslog, or a file path. File destinations are rotated by lumberjack (same as the daemon). Defaults to console.")
	logLevel := flag.String("log-level", "info", "Log level: trace|debug|info|warn|error.")
	flag.Parse()

	if err := util.InitLog(*logLevel, logFiles.values...); err != nil {
		log.Fatalf("init log: %v", err)
	}
	return *daemonAddr
}

// newApplication constructs the Wails application. onSecondInstance is invoked
// when a second process launches under the same SingleInstance UniqueID.
func newApplication(onSecondInstance func()) *application.App {
	// On macOS, application.Options.Icon is fed into NSApplication's
	// setApplicationIconImage at startup, which would override the bundle
	// icon (Assets.car / icons.icns) the OS already picked. We want the
	// bundle's squircle to stay, so suppress it on darwin.
	appIcon := iconWindow
	if runtime.GOOS == "darwin" {
		appIcon = nil
	}

	return application.New(application.Options{
		// Windows uses Name as the AppUserModelID for toast notifications
		// (see notifications_windows.go: cfg.Name -> wn.appName -> AppID)
		// and as the registry path under HKCU\Software\Classes\AppUserModelId\.
		// Must match the System.AppUserModel.ID value the MSI sets on the
		// Start Menu shortcut (client/netbird.wxs) and the AppUserModelId
		// key the installer pre-populates with the toast activator CLSID;
		// otherwise toasts show under a different identity and the MSI's
		// CustomActivator registry value is orphaned.
		Name:        "NetBird",
		Description: "NetBird desktop client",
		Icon:        appIcon,
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: false,
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

// buildI18n constructs the domain-layer i18n bundle, the preferences store,
// and the tray localizer. The Bundle satisfies preferences.LanguageValidator
// so SetLanguage rejects codes that have no shipped translation.
func buildI18n(app *application.App) (*i18n.Bundle, *preferences.Store, *Localizer) {
	// localesFS reroots the embedded tree at the locales directory itself
	// so the bundle sees _index.json and <lang>/common.json at the top
	// level (the //go:embed path is rooted at the package, not the leaf
	// dir).
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
// Services constructed inline here (Session, Forwarding, Debug, I18n,
// Preferences) have no other caller; the rest arrive already built so the
// tray and feed loops can share the same instances.
func registerServices(app *application.App, conn *Conn, s registeredServices) {
	app.RegisterService(application.NewService(s.connection))
	app.RegisterService(application.NewService(services.NewSession(s.authSession)))
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
}

// newMainWindow creates the hidden main window, sized to the user's last view
// mode, and installs the hide-on-close and macOS dock-reopen hooks.
func newMainWindow(app *application.App, prefStore *preferences.Store) *application.WebviewWindow {
	// Open the main window at the width matching the user's last view
	// choice so an Advanced-mode user doesn't see the window pop from 380px
	// to 900px on every launch. Height is the same in both modes.
	initialWidth := 380
	if prefStore.Get().ViewMode == preferences.ViewModeAdvanced {
		initialWidth = 900
	}
	window := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Name:   "main",
		Title:  "NetBird",
		Width:  initialWidth,
		Height: services.WindowHeight,
		// Center on first show. Full DEs (GNOME/KDE) place small windows
		// centered by default, but minimal WMs (fluxbox et al, the XEmbed
		// tray path) drop new windows in the top-left corner unless asked.
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

	// Intercept the window close to hide instead of quit. The user reaches
	// "really quit" via tray -> Quit.
	window.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		e.Cancel()
		window.Hide()
	})

	// On macOS, replace Wails' default applicationShouldHandleReopen handler
	// (events_common_darwin.go setupCommonEvents) which calls Show() on
	// every hidden window when the dock icon is clicked. That resurrects
	// hide-on-close auxiliary surfaces like Settings. Cancel the event in
	// a hook (hooks run synchronously, before listeners) and bring up only
	// the main window. No-op on other platforms — the event never fires.
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
