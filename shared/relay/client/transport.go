package client

import (
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// EnvRelayTransport pins the relay transport. Valid values: "auto" (default,
// race QUIC and WebSocket), "quic" (QUIC only), "ws" (WebSocket only),
// "prefer-quic" / "prefer-ws" (try the preferred transport first, fall back to
// the other only if it fails to connect; no race). The prefer modes trade a
// slower connect when the preferred transport is blackholed for deterministic
// transport selection.
const EnvRelayTransport = "NB_RELAY_TRANSPORT"

const (
	// transportFallbackBase is the initial window a relay server is pinned to
	// WebSocket after a QUIC datagram is rejected as too large.
	transportFallbackBase = 10 * time.Minute
	// transportFallbackMax caps the pinned window when failures repeat.
	transportFallbackMax = 60 * time.Minute
)

// TransportMode selects which relay dialers are used.
type TransportMode string

const (
	TransportModeAuto       TransportMode = "auto"
	TransportModeQUIC       TransportMode = "quic"
	TransportModeWS         TransportMode = "ws"
	TransportModePreferQUIC TransportMode = "prefer-quic"
	TransportModePreferWS   TransportMode = "prefer-ws"
)

// transportModeFromEnv reads EnvRelayTransport, defaulting to auto for an empty
// or unrecognized value.
func transportModeFromEnv() TransportMode {
	switch TransportMode(strings.ToLower(strings.TrimSpace(os.Getenv(EnvRelayTransport)))) {
	case "", TransportModeAuto:
		return TransportModeAuto
	case TransportModeQUIC:
		return TransportModeQUIC
	case TransportModeWS:
		return TransportModeWS
	case TransportModePreferQUIC:
		return TransportModePreferQUIC
	case TransportModePreferWS:
		return TransportModePreferWS
	default:
		log.Warnf("invalid %s value %q, using %q", EnvRelayTransport, os.Getenv(EnvRelayTransport), TransportModeAuto)
		return TransportModeAuto
	}
}

// sequential reports whether the mode tries dialers in order with fallback
// instead of racing them concurrently.
func (m TransportMode) sequential() bool {
	return m == TransportModePreferQUIC || m == TransportModePreferWS
}

// transportFallback tracks relay servers that have failed to carry QUIC
// datagrams and should temporarily use WebSocket instead. It is shared across
// the relay manager so the preference survives client recreation (foreign relay
// clients are evicted and rebuilt on disconnect). Entries are keyed by server
// URL and expire after a window that grows on repeated failures.
type transportFallback struct {
	mu      sync.Mutex
	entries map[string]*fallbackEntry
}

type fallbackEntry struct {
	until    time.Time
	duration time.Duration
}

func newTransportFallback() *transportFallback {
	return &transportFallback{entries: make(map[string]*fallbackEntry)}
}

// preferWS reports whether serverURL is currently within a WebSocket fallback
// window.
func (f *transportFallback) preferWS(serverURL string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.entries[serverURL]
	return e != nil && time.Now().Before(e.until)
}

// recordFailure pins serverURL to WebSocket for a window: transportFallbackBase
// on the first failure, doubling up to transportFallbackMax when QUIC fails
// again after a previous window expired. It returns the active window duration.
func (f *transportFallback) recordFailure(serverURL string) time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()

	now := time.Now()
	e := f.entries[serverURL]
	switch {
	case e == nil:
		e = &fallbackEntry{duration: transportFallbackBase}
		f.entries[serverURL] = e
	case now.Before(e.until):
		return time.Until(e.until)
	default:
		e.duration = min(e.duration*2, transportFallbackMax)
	}
	e.until = now.Add(e.duration)
	return e.duration
}
