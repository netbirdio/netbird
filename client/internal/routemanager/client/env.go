package client

import (
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	// envRouteStickyOnFailure is used to configure if routes should be kept on failure
	envRouteStickyOnFailure = "NB_ROUTE_STICKY_ON_FAILURE"
)

// isRouteStickyOnFailure checks if routes should be kept on failure
func isRouteStickyOnFailure() bool {
	stickyOnFailureEnv := os.Getenv(envRouteStickyOnFailure)
	if stickyOnFailureEnv == "" {
		return false
	}

	log.Infof("routes will be kept on failure as %s is set to %s", envRouteStickyOnFailure, stickyOnFailureEnv)
	return strings.ToLower(stickyOnFailureEnv) == "true"
}
