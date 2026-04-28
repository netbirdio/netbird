//go:build !windows && !android && !ios && !freebsd && !js

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
)

// listenForShowSignal opens the main window when the process receives SIGUSR1.
// External tools (the daemon, the installer, or another `netbird-ui` invocation)
// can poke this channel by signalling the running pid.
func listenForShowSignal(ctx context.Context, tray *Tray) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGUSR1)

	go func() {
		for {
			select {
			case <-ctx.Done():
				signal.Stop(sigCh)
				return
			case <-sigCh:
				log.Debug("SIGUSR1 received, showing window")
				tray.ShowWindow()
			}
		}
	}()
}
