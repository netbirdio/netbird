package peer

import (
	"os"
	"runtime"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	EnvKeyNBForceRelay       = "NB_FORCE_RELAY"
	EnvKeyNBHomeRelayServers = "NB_HOME_RELAY_SERVERS"
)

// ForceRelayFromEnv reports the NB_FORCE_RELAY value of this process and
// whether it is set at all, so a set value can win over the profile setting.
// The JS build has no direct connections and always relays.
func ForceRelayFromEnv() (forced, set bool) {
	if runtime.GOOS == "js" {
		return true, true
	}
	val := os.Getenv(EnvKeyNBForceRelay)
	if val == "" {
		return false, false
	}
	forced, err := strconv.ParseBool(val)
	if err != nil {
		log.Warnf("failed to parse %s: %v", EnvKeyNBForceRelay, err)
		return false, false
	}
	return forced, true
}

// OverrideRelayURLs returns the relay server URL list set in
// NB_HOME_RELAY_SERVERS (comma-separated) and a boolean indicating whether
// the override is active. When the env var is unset, the boolean is false
// and the caller should keep the list received from the management server.
// Intended for lab/debug scenarios where a peer must pin to a specific home
// relay regardless of what management offers.
func OverrideRelayURLs() ([]string, bool) {
	raw := os.Getenv(EnvKeyNBHomeRelayServers)
	if raw == "" {
		return nil, false
	}
	parts := strings.Split(raw, ",")
	urls := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			urls = append(urls, p)
		}
	}
	if len(urls) == 0 {
		return nil, false
	}
	return urls, true
}
