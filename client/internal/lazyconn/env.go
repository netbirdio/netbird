package lazyconn

import (
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	EnvLazyConn            = "NB_LAZY_CONN"
	EnvInactivityThreshold = "NB_LAZY_CONN_INACTIVITY_THRESHOLD"
)

// State is the tri-state local override for lazy connections read from the environment.
type State int

const (
	// StateUnset means no local override; defer to the management feature flag.
	StateUnset State = iota
	// StateOn forces lazy connections on, overriding management.
	StateOn
	// StateOff forces lazy connections off, overriding management.
	StateOff
)

// EnvState reads NB_LAZY_CONN and returns the local override state.
func EnvState() State {
	return ParseState(os.Getenv(EnvLazyConn))
}

// ParseState interprets a lazy-connection override value (from the environment or an MDM
// policy). It accepts the on/off aliases plus any value strconv.ParseBool understands
// (true/false/1/0). An empty or unrecognized value returns StateUnset so that the
// management feature flag remains in control.
func ParseState(raw string) State {
	if raw == "" {
		return StateUnset
	}

	normalized := strings.ToLower(strings.TrimSpace(raw))
	switch normalized {
	case "on":
		return StateOn
	case "off":
		return StateOff
	}

	enabled, err := strconv.ParseBool(normalized)
	if err != nil {
		log.Warnf("failed to parse %s value %q: %v", EnvLazyConn, raw, err)
		return StateUnset
	}
	if enabled {
		return StateOn
	}
	return StateOff
}
