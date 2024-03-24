//go:build !linux || android

package routemanager

import (
	"runtime"

	log "github.com/sirupsen/logrus"
)

func setupRouting() error {
	return nil
}

func cleanupRouting() error {
	return nil
}

func enableIPForwarding() error {
	log.Infof("Enable IP forwarding is not implemented on %s", runtime.GOOS)
	return nil
}
