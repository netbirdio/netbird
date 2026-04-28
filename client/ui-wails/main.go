//go:build !android && !ios && !freebsd && !js

package main

import (
	"context"
	"embed"
	"flag"
	"log"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
	"github.com/wailsapp/wails/v3/pkg/services/notifications"

	"github.com/netbirdio/netbird/client/ui-wails/services"
)

//go:embed all:frontend/dist
var assets embed.FS

func init() {
	application.RegisterEvent[services.Status](services.EventStatus)
	application.RegisterEvent[services.SystemEvent](services.EventSystem)
	application.RegisterEvent[services.UpdateAvailable](services.EventUpdateAvailable)
	application.RegisterEvent[services.UpdateProgress](services.EventUpdateProgress)
}

func main() {
	daemonAddr := flag.String("daemon-addr", DaemonAddr(), "Daemon gRPC address: unix:///path or tcp://host:port")
	flag.Parse()

	conn := NewConn(*daemonAddr)

	// tray is captured in the SingleInstance callback below; the var is
	// declared before app.New so the closure has a stable reference.
	var tray *Tray

	app := application.New(application.Options{
		Name:        "netbird-ui",
		Description: "NetBird desktop client",
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: false,
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
	notifier := notifications.New()

	app.RegisterService(application.NewService(connection))
	app.RegisterService(application.NewService(settings))
	app.RegisterService(application.NewService(services.NewNetworks(conn)))
	app.RegisterService(application.NewService(profiles))
	app.RegisterService(application.NewService(services.NewDebug(conn)))
	app.RegisterService(application.NewService(services.NewUpdate(conn)))
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
	})

	// Intercept the window close to hide instead of quit. The user reaches
	// "really quit" via tray -> Quit.
	window.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		e.Cancel()
		window.Hide()
	})

	tray = NewTray(app, window, connection, settings, profiles, peers, notifier)
	listenForShowSignal(context.Background(), tray)

	peers.Watch(context.Background())

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
