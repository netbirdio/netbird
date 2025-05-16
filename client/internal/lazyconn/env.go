package lazyconn

import (
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
)

const (
	EnvEnableLazyConn      = "NB_ENABLE_EXPERIMENTAL_LAZY_CONN"
	EnvInactivityThreshold = "NB_LAZY_CONN_INACTIVITY_THRESHOLD"
)

func IsLazyConnEnabledByEnv() bool {
	val := os.Getenv(EnvEnableLazyConn)
	if val == "" {
		return false
	}
	enabled, err := strconv.ParseBool(val)
	if err != nil {
		log.Warnf("failed to parse %s: %v", EnvEnableLazyConn, err)
		return false
	}
	return enabled
}
