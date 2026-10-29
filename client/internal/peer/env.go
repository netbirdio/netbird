package peer

import (
	"os"
	"runtime"
	"strings"
)

const (
	EnvKeyNBForceRelay       = "NB_FORCE_RELAY"
	EnvKeyNBHomeRelayServers = "NB_HOME_RELAY_SERVERS"
)

func IsForceRelayed() bool {
	if runtime.GOOS == "js" {
		return true
	}
	return strings.EqualFold(os.Getenv(EnvKeyNBForceRelay), "true")
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
