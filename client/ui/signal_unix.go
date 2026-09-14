//go:build !windows && !android && !ios && !freebsd && !js

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
)

// listenForShowSignal lets external tools surface the running UI by signalling its pid (SIGUSR1).
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
