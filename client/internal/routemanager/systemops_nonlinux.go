//go:build !linux || android

package routemanager

import (
	"runtime"

	log "github.com/sirupsen/logrus"
)

func enableIPForwarding() error {
	log.Infof("Enable IP forwarding is not implemented on %s", runtime.GOOS)
	return nil
}
