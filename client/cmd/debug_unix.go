//go:build unix

package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal"
	"github.com/netbirdio/netbird/client/internal/peer"
)

func SetupDebugHandler(
	ctx context.Context,
	config *internal.Config,
	recorder *peer.Status,
	connectClient *internal.ConnectClient,
	logFilePath string,
) {
	usr1Ch := make(chan os.Signal, 1)

	signal.Notify(usr1Ch, syscall.SIGUSR1)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-usr1Ch:
				log.Info("Received SIGUSR1. Triggering debug bundle generation.")
				go generateDebugBundle(config, recorder, connectClient, logFilePath)
			}
		}
	}()
}
