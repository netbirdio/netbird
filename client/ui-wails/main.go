//go:build !android && !ios && !freebsd && !js

package main

import (
	"context"
	"embed"
	"flag"
	"log"
	"strings"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
	"github.com/wailsapp/wails/v3/pkg/services/notifications"

	"github.com/netbirdio/netbird/client/ui-wails/services"
	"github.com/netbirdio/netbird/util"
)

//go:embed all:frontend/dist
var assets embed.FS

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
	application.RegisterEvent[services.UpdateAvailable](services.EventUpdateAvailable)
	application.RegisterEvent[services.UpdateProgress](services.EventUpdateProgress)
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

	app := application.New(application.Options{
		Name:        "netbird-ui",
		Description: "NetBird desktop client",
		Icon:        iconWindow,
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
	peers := services.NewPeers(conn, app.Event)
	update := services.NewUpdate(conn)
	notifier := notifications.New()

	app.RegisterService(application.NewService(connection))
	app.RegisterService(application.NewService(settings))
	app.RegisterService(application.NewService(services.NewNetworks(conn)))
	app.RegisterService(application.NewService(services.NewForwarding(conn)))
	app.RegisterService(application.NewService(profiles))
	app.RegisterService(application.NewService(services.NewDebug(conn)))
	app.RegisterService(application.NewService(update))
	app.RegisterService(application.NewService(peers))
	app.RegisterService(application.NewService(notifier))

	window := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "NetBird",
		Width:            960,
		Height:           640,
		Hidden:           false,
		BackgroundColour: application.NewRGB(24, 26, 29),
		URL:              "/",
		Mac: application.MacWindow{
			InvisibleTitleBarHeight: 38,
			Backdrop:                application.MacBackdropTranslucent,
			TitleBar:                application.MacTitleBarHiddenInset,
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

	tray = NewTray(app, window, TrayServices{
		Connection: connection,
		Settings:   settings,
		Profiles:   profiles,
		Peers:      peers,
		Notifier:   notifier,
		Update:     update,
	})
	listenForShowSignal(context.Background(), tray)

	peers.Watch(context.Background())

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
