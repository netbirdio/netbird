package pqkem

import (
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// EnvEnabled is the environment variable that turns the ML-KEM post-quantum
// exchange on for this client. Accepts on/off aliases plus anything
// strconv.ParseBool understands (true/false/1/0).
const EnvEnabled = "NB_ENABLE_PQ_MLKEM"

// Enabled reports whether the ML-KEM PQ exchange is enabled via the environment.
// An empty or unrecognized value is treated as disabled.
func Enabled() bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(EnvEnabled)))
	switch raw {
	case "":
		return false
	case "on":
		return true
	case "off":
		return false
	}
	enabled, err := strconv.ParseBool(raw)
	if err != nil {
		log.Warnf("failed to parse %s value %q: %v", EnvEnabled, raw, err)
		return false
	}
	return enabled
}
