package client

import (
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/relay/client/dialer"
)

// EnvRelayTransport pins the relay transport. Valid values: "auto" (default,
// race QUIC and WebSocket), "quic" (QUIC only), "ws" (WebSocket only),
// "prefer-quic" / "prefer-ws" (try the preferred transport first, fall back to
// the other only if it fails to connect; no race). The prefer modes trade a
// slower connect when the preferred transport is blackholed for deterministic
// transport selection.
const EnvRelayTransport = "NB_RELAY_TRANSPORT"

const (
	// transportFallbackBase is the initial window a relay server avoids
	// datagram-sized transports after a datagram is rejected as too large.
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

// transportFallback tracks relay servers that have rejected a datagram-sized
// transport (a write too large for the path) and should temporarily avoid such
// transports. It is shared across the relay manager so the preference survives
// client recreation (foreign relay clients are evicted and rebuilt on
// disconnect). Entries are keyed by server URL and expire after a window that
// grows on repeated failures.
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

// avoidDatagramSized reports whether serverURL is currently within a window
// where datagram-sized transports should be avoided.
func (f *transportFallback) avoidDatagramSized(serverURL string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.entries[serverURL]
	return e != nil && time.Now().Before(e.until)
}

// recordFailure makes serverURL avoid datagram-sized transports for a window:
// transportFallbackBase on the first failure, doubling up to transportFallbackMax
// when a datagram transport fails again after a previous window expired. It
// returns the active window duration.
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

// nonDatagramSized returns the dialers from in that are not datagram-sized,
// preserving order.
func nonDatagramSized(in []dialer.DialeFn) []dialer.DialeFn {
	out := make([]dialer.DialeFn, 0, len(in))
	for _, d := range in {
		if !dialer.IsDatagramSized(d) {
			out = append(out, d)
		}
	}
	return out
}
