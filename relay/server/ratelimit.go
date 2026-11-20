package server

import (
	"encoding/base64"
	"fmt"
	"math"
	"strconv"
	"strings"

	"golang.org/x/time/rate"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

const (
	// minBurstBytes keeps the bucket above messages.MaxMessageSize so a single
	// relayed datagram always fits.
	minBurstBytes = 16 << 10
	// maxBurstBytes caps the bucket at high rates, where one second of budget
	// would let several megabytes through at line rate.
	maxBurstBytes = 8 << 20
)

// RateLimitConfig describes optional bandwidth limits applied when the relay
// forwards transport traffic to a destination peer. Limits are bit rates such
// as "50mbps", keyed by the destination peer relay ID (either its "sha-..."
// relay identity or its WireGuard public key, which is hashed with the same
// scheme the client uses).
//
// When Enabled is false all limits are ignored and forwarding is unlimited.
// The zero value therefore keeps the previous behaviour.
type RateLimitConfig struct {
	Enabled bool
	// Default gives every destination peer without an explicit entry its own
	// budget. Empty or "unlimited" means no limit.
	Default string
	// Peers maps a destination peer to its limit, overriding Default.
	// "unlimited" exempts the peer from Default.
	Peers map[string]string
}

// limiterSet resolves the limiter for traffic forwarded to a destination peer.
type limiterSet struct {
	def rate.Limit
	// peers holds the explicit entries; a nil limiter marks an unlimited peer.
	peers map[messages.PeerID]*rate.Limiter
}

func newLimiterSet(cfg RateLimitConfig) (*limiterSet, error) {
	s := &limiterSet{def: rate.Inf}
	if !cfg.Enabled {
		return s, nil
	}

	def, err := parseRate(cfg.Default)
	if err != nil {
		return nil, fmt.Errorf("invalid default rate limit %q: %w", cfg.Default, err)
	}
	s.def = def

	s.peers = make(map[messages.PeerID]*rate.Limiter, len(cfg.Peers))
	for key, spec := range cfg.Peers {
		id, err := parsePeerIDKey(key)
		if err != nil {
			return nil, fmt.Errorf("invalid rate limit peer key %q: %w", key, err)
		}
		if _, dup := s.peers[id]; dup {
			return nil, fmt.Errorf("duplicate rate limit for peer %q", key)
		}
		limit, err := parseRate(spec)
		if err != nil {
			return nil, fmt.Errorf("invalid rate limit for peer %q: %w", key, err)
		}
		s.peers[id] = newLimiter(limit)
	}

	return s, nil
}

// forPeer returns the limiter for traffic forwarded to the given peer, or nil
// when the peer is unlimited. Explicit entries keep their budget across
// reconnects; the default starts a fresh budget for every connection.
func (s *limiterSet) forPeer(id messages.PeerID) *rate.Limiter {
	if s == nil {
		return nil
	}
	if l, ok := s.peers[id]; ok {
		return l
	}
	return newLimiter(s.def)
}

// newLimiter returns nil for rate.Inf. The bucket holds one second of traffic,
// bounded by minBurstBytes and maxBurstBytes.
func newLimiter(limit rate.Limit) *rate.Limiter {
	if limit == rate.Inf {
		return nil
	}

	burst := maxBurstBytes
	if limit < maxBurstBytes {
		burst = max(int(limit), minBurstBytes)
	}
	return rate.NewLimiter(limit, burst)
}

// parseRate converts a bit rate with a bps, kbps, mbps or gbps unit into bytes
// per second. Matching is case-insensitive. "", "0", "off", "none" and
// "unlimited" mean no limit.
func parseRate(spec string) (rate.Limit, error) {
	s := strings.ToLower(strings.TrimSpace(spec))
	switch s {
	case "", "0", "off", "none", "unlimited":
		return rate.Inf, nil
	}

	units := []struct {
		suffix string
		bits   float64
	}{
		{"gbps", 1e9},
		{"mbps", 1e6},
		{"kbps", 1e3},
		{"bps", 1},
	}

	for _, u := range units {
		num, ok := strings.CutSuffix(s, u.suffix)
		if !ok {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(num), 64)
		if err != nil || v < 0 || math.IsNaN(v) || math.IsInf(v, 0) {
			return 0, fmt.Errorf("cannot parse %q: expected a non-negative number before %s", spec, u.suffix)
		}
		if v == 0 {
			return rate.Inf, nil
		}
		return rate.Limit(v * u.bits / 8), nil
	}

	return 0, fmt.Errorf("cannot parse %q: expected a number followed by bps, kbps, mbps or gbps", spec)
}

// parsePeerIDKey accepts either the relay peer identity ("sha-" followed by the
// base64 encoded hash) or the peer WireGuard public key, which the client hashes
// with messages.HashID before connecting to the relay.
func parsePeerIDKey(key string) (messages.PeerID, error) {
	k := strings.TrimSpace(key)
	encoded, isRelayID := strings.CutPrefix(k, "sha-")

	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return messages.PeerID{}, fmt.Errorf("invalid base64: %w", err)
	}
	if len(raw) != 32 {
		return messages.PeerID{}, fmt.Errorf("invalid length %d, expected 32 bytes", len(raw))
	}
	if !isRelayID {
		return messages.HashID(k), nil
	}

	var id messages.PeerID
	copy(id[:4], []byte("sha-"))
	copy(id[4:], raw)
	return id, nil
}
