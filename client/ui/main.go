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

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
	"github.com/wailsapp/wails/v3/pkg/services/notifications"

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
//go:embed all:frontend/src/i18n/locales
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

func init() {
	application.RegisterEvent[services.Status](services.EventStatus)
	application.RegisterEvent[services.SystemEvent](services.EventSystem)
	application.RegisterEvent[services.ProfileRef](services.EventProfileChanged)
	application.RegisterEvent[updater.State](updater.EventStateChanged)
	application.RegisterEvent[preferences.UIPreferences](preferences.EventPreferencesChanged)
}

func main() {
	daemonAddr := flag.String("daemon-addr", DaemonAddr(), "Daemon gRPC address: unix:///path or tcp://host:port")
	logFiles := &stringList{values: []string{"console"}}
	flag.Var(logFiles, "log-file", "Log destination. Repeat to log to multiple targets at once, e.g. `--log-file console --log-file Y:/netbird-ui.log`. Each value is one of: console, syslog, or a file path. File destinations are rotated by lumberjack (same as the daemon). Defaults to console.")
	logLevel := flag.String("log-level", "info", "Log level: trace|debug|info|warn|error.")
	flag.Parse()

	if err := util.InitLog(*logLevel, logFiles.values...); err != nil {
		log.Fatalf("init log: %v", err)
	}

	conn := NewConn(*daemonAddr)

	// tray is captured in the SingleInstance callback below; the var is
	// declared before app.New so the closure has a stable reference.
	var tray *Tray

	// On macOS, application.Options.Icon is fed into NSApplication's
	// setApplicationIconImage at startup, which would override the bundle
	// icon (Assets.car / icons.icns) the OS already picked. We want the
	// bundle's squircle to stay, so suppress it on darwin.
	appIcon := iconWindow
	if runtime.GOOS == "darwin" {
		appIcon = nil
	}

	app := application.New(application.Options{
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
				if tray != nil {
					tray.ShowWindow()
				}
			},
		},
	})

	connection := services.NewConnection(conn)
	settings := services.NewSettings(conn)
	profiles := services.NewProfiles(conn)
	// updater.Holder owns the typed update State. Peers feeds the daemon
	// SubscribeEvents stream into it; the Update service is a thin
	// Wails-bound facade over the holder plus the install RPCs.
	updaterHolder := updater.NewHolder(app.Event)
	update := services.NewUpdate(conn, updaterHolder)
	peers := services.NewPeers(conn, app.Event, updaterHolder)
	notifier := notifications.New()
	profileSwitcher := services.NewProfileSwitcher(profiles, connection, peers)

	// localesFS reroots the embedded tree at the locales directory itself
	// so the bundle sees _index.json and <lang>/common.json at the top
	// level (the //go:embed path is rooted at the package, not the leaf
	// dir).
	localesFS, err := fs.Sub(localesRoot, "frontend/src/i18n/locales")
	if err != nil {
		log.Fatalf("locate locales fs: %v", err)
	}
	// Build the domain layer first, then wrap it in the Wails-bound
	// services. The Bundle satisfies preferences.LanguageValidator so
	// SetLanguage rejects codes that have no shipped translation.
	bundle, err := i18n.NewBundle(localesFS)
	if err != nil {
		log.Fatalf("init i18n bundle: %v", err)
	}
	prefStore, err := preferences.NewStore(bundle, app.Event)
	if err != nil {
		log.Fatalf("init preferences store: %v", err)
	}
	localizer := NewLocalizer(bundle, prefStore)

	app.RegisterService(application.NewService(connection))
	app.RegisterService(application.NewService(settings))
	app.RegisterService(application.NewService(services.NewNetworks(conn)))
	app.RegisterService(application.NewService(services.NewForwarding(conn)))
	app.RegisterService(application.NewService(profiles))
	app.RegisterService(application.NewService(services.NewDebug(conn)))
	app.RegisterService(application.NewService(update))
	app.RegisterService(application.NewService(peers))
	app.RegisterService(application.NewService(notifier))
	app.RegisterService(application.NewService(profileSwitcher))
	app.RegisterService(application.NewService(services.NewI18n(bundle)))
	app.RegisterService(application.NewService(services.NewPreferences(prefStore)))

	window := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:               "NetBird",
		Width:               310,
		Height:              420,
		Hidden:              true,
		BackgroundColour:    application.NewRGB(24, 26, 29),
		URL:                 "/",
		MaximiseButtonState: application.ButtonHidden,
		Mac: application.MacWindow{
			InvisibleTitleBarHeight: 38,
			Backdrop:                application.MacBackdropNormal,
			TitleBar:                application.MacTitleBarHiddenInset,
			CollectionBehavior:      application.MacWindowCollectionBehaviorFullScreenNone,
		},
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

	// The settings and browser-login windows are created lazily and
	// destroyed on close, so they don't linger as hidden windows that
	// Wails's macOS dock-reopen handler would pop back up.
	windowManager := services.NewWindowManager(app, window)
	app.RegisterService(application.NewService(windowManager))

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
		Peers:           peers,
		Notifier:        notifier,
		Update:          update,
		ProfileSwitcher: profileSwitcher,
		WindowManager:   windowManager,
		Localizer:       localizer,
	})
	listenForShowSignal(context.Background(), tray)

	peers.Watch(context.Background())

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
