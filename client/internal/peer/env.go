package peer

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
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

// EnvKeyNBTestRelayWgKaOff is a test knob. When true, a relayed peer keeps the
// WireGuard persistent keepalive only until the first handshake, then sets it to 0,
// and the WireGuard watcher stops its periodic check on the relay path.
const EnvKeyNBTestRelayWgKaOff = "NB_TEST_RELAY_WG_KA_OFF"

var relayWgKaOff = sync.OnceValue(func() bool {
	val := os.Getenv(EnvKeyNBTestRelayWgKaOff)
	if val == "" {
		return false
	}
	off, err := strconv.ParseBool(val)
	if err != nil {
		log.Warnf("failed to parse %s: %v", EnvKeyNBTestRelayWgKaOff, err)
		return false
	}
	log.Infof("wgka: %s=%t", EnvKeyNBTestRelayWgKaOff, off)
	return off
})

// isRelayWgKaOff reports the NB_TEST_RELAY_WG_KA_OFF knob, read once per process.
func isRelayWgKaOff() bool {
	return relayWgKaOff()
}
