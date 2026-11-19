package server

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

const (
	// minBurstBytes is the smallest token bucket size we accept. It must stay
	// comfortably above messages.MaxMessageSize so a single relayed datagram
	// can always be admitted by rate.Limiter.WaitN.
	minBurstBytes = 16 << 10
	// maxBurstBytes caps the bucket so a very high configured rate does not
	// allow large bursts above what a single WireGuard datagram needs.
	maxBurstBytes = 8 << 20

	// rateLimitWaitTimeout bounds how long a sender waits for budget before the
	// message is dropped. It stays well below the relay healthcheck timeout
	// (default interval + 10s) so a throttled peer is not disconnected.
	rateLimitWaitTimeout = 2 * time.Second
)

// RateLimitConfig describes optional bandwidth limits applied when the relay
// forwards transport traffic to a destination peer. Limits are expressed as
// bytes or bits per second and are keyed by the destination peer relay ID
// (either its "sha-..." relay identity or its WireGuard public key, which is
// hashed with the same scheme the client uses).
//
// When Enabled is false all limits are ignored and forwarding is unlimited.
// The zero value therefore keeps the previous behaviour.
type RateLimitConfig struct {
	Enabled bool
	// Default applies to every destination peer that has no explicit entry.
	// Empty or "unlimited" means no limit.
	Default string
	// Peers maps a destination peer to its limit, overriding Default.
	Peers map[string]string
}

// limiterSet resolves a limiter per destination peer. A nil limiter means the
// destination is not limited.
type limiterSet struct {
	def   *rate.Limiter
	peers map[messages.PeerID]*rate.Limiter
}

func newLimiterSet(cfg RateLimitConfig) (*limiterSet, error) {
	s := &limiterSet{peers: make(map[messages.PeerID]*rate.Limiter, len(cfg.Peers))}
	if !cfg.Enabled {
		return s, nil
	}

	def, err := newLimiter(cfg.Default)
	if err != nil {
		return nil, fmt.Errorf("invalid default rate limit %q: %w", cfg.Default, err)
	}
	s.def = def

	for key, spec := range cfg.Peers {
		id, err := parsePeerIDKey(key)
		if err != nil {
			return nil, fmt.Errorf("invalid rate limit peer key %q: %w", key, err)
		}
		l, err := newLimiter(spec)
		if err != nil {
			return nil, fmt.Errorf("invalid rate limit for peer %q: %w", key, err)
		}
		if l != nil {
			s.peers[id] = l
		}
	}

	return s, nil
}

// forDst returns the limiter that applies to the given destination peer, or
// nil when the destination is unlimited.
func (s *limiterSet) forDst(id messages.PeerID) *rate.Limiter {
	if s == nil {
		return nil
	}
	if l, ok := s.peers[id]; ok {
		return l
	}
	return s.def
}

func newLimiter(spec string) (*rate.Limiter, error) {
	lim, err := parseRate(spec)
	if err != nil {
		return nil, err
	}
	if lim == rate.Inf || lim <= 0 {
		return nil, nil
	}

	burst := int(lim)
	if burst < minBurstBytes {
		burst = minBurstBytes
	}
	if burst > maxBurstBytes {
		burst = maxBurstBytes
	}
	return rate.NewLimiter(lim, burst), nil
}

// parseRate converts a human readable rate into bytes per second. Supported
// forms are "unlimited"/"off"/"0"/"" for no limit, a bare number interpreted as
// bytes per second, and a number followed by one of the units bps, kbps, mbps,
// gbps (bits), b/s, kb/s, mb/s, gb/s, byte/s (bytes). Matching is
// case-insensitive and a "/s" suffix is optional for the bit units.
func parseRate(spec string) (rate.Limit, error) {
	s := strings.ToLower(strings.TrimSpace(spec))
	switch s {
	case "", "0", "off", "none", "unlimited":
		return rate.Inf, nil
	}

	units := []struct {
		suffix string
		mul    float64
	}{
		{"gbps", 1e9 / 8},
		{"gbit/s", 1e9 / 8},
		{"gb/s", 1e9},
		{"mbps", 1e6 / 8},
		{"mbit/s", 1e6 / 8},
		{"mb/s", 1e6},
		{"kbps", 1e3 / 8},
		{"kbit/s", 1e3 / 8},
		{"kb/s", 1e3},
		{"bps", 1 / 8.0},
		{"bit/s", 1 / 8.0},
		{"bytes/s", 1},
		{"byte/s", 1},
		{"b/s", 1},
	}

	for _, u := range units {
		if !strings.HasSuffix(s, u.suffix) {
			continue
		}
		raw := strings.TrimSpace(strings.TrimSuffix(s, u.suffix))
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil {
			return 0, fmt.Errorf("cannot parse %q: %w", spec, err)
		}
		if v < 0 {
			return 0, fmt.Errorf("rate must not be negative: %q", spec)
		}
		if v == 0 {
			return rate.Inf, nil
		}
		return rate.Limit(v * u.mul), nil
	}

	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("cannot parse %q: expected a number with an optional unit such as 50mbps", spec)
	}
	if v < 0 {
		return 0, fmt.Errorf("rate must not be negative: %q", spec)
	}
	if v == 0 {
		return rate.Inf, nil
	}
	return rate.Limit(v), nil
}

// parsePeerIDKey accepts either the relay peer identity ("sha-" followed by the
// base64 encoded hash) or the peer WireGuard public key, which the client hashes
// with messages.HashID before connecting to the relay.
func parsePeerIDKey(key string) (messages.PeerID, error) {
	k := strings.TrimSpace(key)
	if k == "" {
		return messages.PeerID{}, fmt.Errorf("empty peer key")
	}
	if !strings.HasPrefix(k, "sha-") {
		return messages.HashID(k), nil
	}

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(k, "sha-"))
	if err != nil {
		return messages.PeerID{}, fmt.Errorf("invalid base64 relay id: %w", err)
	}
	if len(raw) != 32 {
		return messages.PeerID{}, fmt.Errorf("invalid relay id length %d, expected 32 bytes", len(raw))
	}

	var id messages.PeerID
	copy(id[:4], []byte("sha-"))
	copy(id[4:], raw)
	return id, nil
}
