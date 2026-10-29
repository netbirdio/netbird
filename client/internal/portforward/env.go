package portforward

import (
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
)

const (
	envDisableNATMapper      = "NB_DISABLE_NAT_MAPPER"
	envDisablePCPHealthCheck = "NB_DISABLE_PCP_HEALTH_CHECK"
)

func isDisabledByEnv() bool {
	return parseBoolEnv(envDisableNATMapper)
}

func isHealthCheckDisabled() bool {
	return parseBoolEnv(envDisablePCPHealthCheck)
}

func parseBoolEnv(key string) bool {
	val := os.Getenv(key)
	if val == "" {
		return false
	}

	disabled, err := strconv.ParseBool(val)
	if err != nil {
		log.Warnf("failed to parse %s: %v", key, err)
		return false
	}
	return disabled
}
