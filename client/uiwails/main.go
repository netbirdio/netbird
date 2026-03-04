//go:build !(linux && 386)

package main

import (
	"context"
	"embed"
	"flag"
	"os"
	"runtime"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
	"github.com/wailsapp/wails/v3/pkg/services/notifications"

	"github.com/netbirdio/netbird/client/uiwails/event"
	"github.com/netbirdio/netbird/client/uiwails/process"
	"github.com/netbirdio/netbird/client/uiwails/services"
)

//go:embed frontend/dist
var frontendFS embed.FS

var (
	daemonAddr = flag.String("daemon-addr", defaultDaemonAddr(), "NetBird daemon gRPC address")
)

func defaultDaemonAddr() string {
	if runtime.GOOS == "windows" {
		return "tcp://127.0.0.1:41731"
	}
	return "unix:///var/run/netbird.sock"
}

func main() {
	flag.Parse()

	// Single-instance guard — if another instance is running, show its window and exit.
	if pid, running, err := process.IsAnotherProcessRunning(); err == nil && running {
		log.Infof("another instance is running (pid %d), signalling it to show window", pid)
		if err := sendShowWindowSignal(pid); err != nil {
			log.Warnf("send show window signal: %v", err)
		}
		os.Exit(0)
	}

	grpcClient := NewGRPCClient(*daemonAddr)

	connSvc := services.NewConnectionService(grpcClient)
	settingsSvc := services.NewSettingsService(grpcClient)
	networkSvc := services.NewNetworkService(grpcClient)
	profileSvc := services.NewProfileService(grpcClient)
	peersSvc := services.NewPeersService(grpcClient)
	debugSvc := services.NewDebugService(grpcClient)
	updateSvc := services.NewUpdateService(grpcClient)
	notifSvc := notifications.New()

	app := application.New(application.Options{
		Name:        "NetBird",
		Description: "NetBird VPN client",
		Services: []application.Service{
			application.NewService(connSvc),
			application.NewService(settingsSvc),
			application.NewService(networkSvc),
			application.NewService(profileSvc),
			application.NewService(peersSvc),
			application.NewService(debugSvc),
			application.NewService(updateSvc),
			application.NewService(notifSvc),
		},
		Assets: application.AssetOptions{
			Handler: application.BundledAssetFileServer(frontendFS),
		},
		Mac: application.MacOptions{
			ActivationPolicy: application.ActivationPolicyAccessory,
		},
	})

	window := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:         "NetBird",
		Width:         900,
		Height:        650,
		Hidden:        true, // start hidden — tray is the primary interface
		URL:           "/",
		AlwaysOnTop:   false,
		DisableResize: false,
		Windows: application.WindowsWindow{
			HiddenOnTaskbar: true,
		},
	})

	// Hide instead of quit when user closes the window.
	window.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		e.Cancel()
		window.Hide()
	})

	// Register an in-process StatusNotifierWatcher so the tray works on
	// minimal WMs (Fluxbox, OpenBox, i3…) that don't ship one themselves.
	startStatusNotifierWatcher()

	tray := newTrayManager(app, window, connSvc, settingsSvc, networkSvc, profileSvc)
	tray.Setup(iconDisconnected)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Signal handler: SIGUSR1 on Unix, Windows Event on Windows.
	setupSignalHandler(ctx, window)

	// Daemon event stream → desktop notifications.
	notify := func(title, body string) {
		if err := notifSvc.SendNotification(notifications.NotificationOptions{
			ID:    "netbird-event",
			Title: title,
			Body:  body,
		}); err != nil {
			log.Warnf("send notification: %v", err)
		}
	}

	evtManager := event.NewManager(*daemonAddr, notify)
	go evtManager.Start(ctx)

	// TEST: fire a desktop notification shortly after startup so we can
	// verify that the notification pipeline works end-to-end.
	go func() {
		time.Sleep(3 * time.Second)
		log.Infof("--- trigger notification ---")
		notify("NetBird Test", "If you see this, notifications are working!")
	}()

	if err := app.Run(); err != nil {
		log.Fatalf("app run: %v", err)
	}
}
