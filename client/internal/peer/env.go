package peer

import (
	"os"
	"runtime"
	"strings"

	"gvisor.dev/gvisor/pkg/log"
)

const (
	EnvKeyNBForceRelay = "NB_FORCE_RELAY"
	// EnvKeepConnectionOnMgmtDown controls whether peer and routes are kept even when ice peers are considered unavailable and the management connection is down.
	EnvKeepConnectionOnMgmtDown = "NB_KEEP_CONNECTION_ON_MANAGEMENT_DOWN"
)

func isForceRelayed() bool {
	if runtime.GOOS == "js" {
		return true
	}
	return strings.EqualFold(os.Getenv(EnvKeyNBForceRelay), "true")
}

// isConnectionKeepOnMgmtDown checks if peers and routes should be kept when management connection is down
func IsKeepConnectionOnMgmtDown() bool {
	stickyOnManagementDownEnv := os.Getenv(EnvKeepConnectionOnMgmtDown)
	if stickyOnManagementDownEnv == "" {
		return false
	}

	log.Infof("peers will be kept on failure as %s is set to %s", EnvKeepConnectionOnMgmtDown, stickyOnManagementDownEnv)
	return strings.ToLower(stickyOnManagementDownEnv) == "true"
}
