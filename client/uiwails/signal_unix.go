//go:build !windows && !(linux && 386)

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/wailsapp/wails/v3/pkg/application"
)

// setupSignalHandler listens for SIGUSR1 and shows the main window when received.
func setupSignalHandler(ctx context.Context, window *application.WebviewWindow) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGUSR1)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigChan:
				log.Info("received SIGUSR1 signal, showing window")
				window.Show()
			}
		}
	}()
}

// sendShowWindowSignal sends SIGUSR1 to an already-running instance to trigger window show.
func sendShowWindowSignal(pid int32) error {
	proc, err := os.FindProcess(int(pid))
	if err != nil {
		return err
	}
	return proc.Signal(syscall.SIGUSR1)
}
