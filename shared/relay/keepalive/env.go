package keepalive

import (
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	envInterval        = "NB_RELAY_KA_INTERVAL"
	envResponseTimeout = "NB_RELAY_KA_RESPONSE_TIMEOUT"
	envAllowance       = "NB_RELAY_KA_ALLOWANCE"

	defaultInterval        = 60 * time.Second
	defaultResponseTimeout = 20 * time.Second
	defaultAllowance       = 120 * time.Second
)

func durationFromEnv(name string, fallback time.Duration) time.Duration {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		log.Warnf("invalid duration %q in %s, using %s", value, name, fallback)
		return fallback
	}
	return d
}
