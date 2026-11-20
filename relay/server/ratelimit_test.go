package server

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"

	"github.com/netbirdio/netbird/shared/relay/auth/allow"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

func TestParseRate(t *testing.T) {
	tests := []struct {
		spec    string
		want    rate.Limit
		wantErr bool
	}{
		{spec: "", want: rate.Inf},
		{spec: "0", want: rate.Inf},
		{spec: "unlimited", want: rate.Inf},
		{spec: "0mbps", want: rate.Inf},
		{spec: "800bps", want: 100},
		{spec: "100kbps", want: 12_500},
		{spec: "50mbps", want: 6_250_000},
		{spec: " 50 Mbps ", want: 6_250_000},
		{spec: "1.5gbps", want: 187_500_000},
		// A bare number does not say whether it counts bits or bytes.
		{spec: "50", wantErr: true},
		// Byte units are not accepted: lower-cased, "Mb/s" would read as megabytes.
		{spec: "6.25MB/s", wantErr: true},
		{spec: "100Mb/s", wantErr: true},
		{spec: "-1mbps", wantErr: true},
		{spec: "nanmbps", wantErr: true},
		{spec: "infmbps", wantErr: true},
		{spec: "fast", wantErr: true},
	}

	for _, tc := range tests {
		got, err := parseRate(tc.spec)
		if tc.wantErr {
			assert.Error(t, err, "parseRate(%q) must fail", tc.spec)
			continue
		}
		require.NoError(t, err, "parseRate(%q)", tc.spec)
		assert.InDelta(t, float64(tc.want), float64(got), 1e-6, "parseRate(%q) in bytes per second", tc.spec)
	}
}

func TestParsePeerIDKey(t *testing.T) {
	// A WireGuard public key is the base64 encoding of 32 bytes, and the client
	// registers at the relay with the hash of that string.
	pubKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	relayID := messages.HashID(pubKey)

	tests := []struct {
		name    string
		key     string
		want    messages.PeerID
		wantErr bool
	}{
		{name: "public key", key: pubKey, want: relayID},
		{name: "relay id", key: relayID.String(), want: relayID},
		{name: "empty", key: "", wantErr: true},
		{name: "truncated public key", key: pubKey[:len(pubKey)-2] + "=", wantErr: true},
		{name: "not a key", key: "peer-public-key", wantErr: true},
		{name: "relay id with invalid base64", key: "sha-notbase64!", wantErr: true},
		{name: "relay id of wrong length", key: "sha-" + base64.StdEncoding.EncodeToString(make([]byte, 16)), wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePeerIDKey(tc.key)
			if tc.wantErr {
				assert.Error(t, err, "a malformed key must fail at startup")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got, "the key must resolve to the peer's relay id")
		})
	}
}

func TestNewRelay_RejectsInvalidRateLimit(t *testing.T) {
	pubKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	tests := map[string]RateLimitConfig{
		"default":   {Enabled: true, Default: "fast"},
		"peer key":  {Enabled: true, Peers: map[string]string{"not-a-key": "10mbps"}},
		"peer rate": {Enabled: true, Peers: map[string]string{relayKey("peer"): "10"}},
		// The same peer by public key and by relay id: which limit wins would
		// depend on map iteration order.
		"duplicate peer": {Enabled: true, Peers: map[string]string{
			pubKey:                           "10mbps",
			messages.HashID(pubKey).String(): "20mbps",
		}},
	}

	for name, cfg := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := NewRelay(Config{
				ExposedAddress: "rel://127.0.0.1:1234",
				AuthValidator:  &allow.Auth{},
				RateLimit:      cfg,
			})
			assert.Error(t, err, "an invalid rate limit must stop the relay from starting")
		})
	}
}

// Frames carry 1400 bytes of payload plus the 38-byte transport header, so the
// 16 KiB bucket of a slow limit admits 11 of them. At 8bps (1 byte per second)
// the bucket does not refill during the test.
func TestPeer_RateLimitBudgets(t *testing.T) {
	type send struct {
		dst    string
		frames int
	}
	tests := []struct {
		name  string
		limit RateLimitConfig
		sends []send
		want  map[string]int
	}{
		{
			name:  "frames over an explicit limit are dropped",
			limit: RateLimitConfig{Enabled: true, Peers: map[string]string{relayKey("dst-a"): "8bps"}},
			sends: []send{{dst: "dst-a", frames: 15}},
			want:  map[string]int{"dst-a": 11},
		},
		{
			name:  "the default gives each destination its own budget",
			limit: RateLimitConfig{Enabled: true, Default: "8bps"},
			sends: []send{{dst: "dst-a", frames: 11}, {dst: "dst-b", frames: 11}},
			want:  map[string]int{"dst-a": 11, "dst-b": 11},
		},
		{
			name: "an unlimited entry overrides the default",
			limit: RateLimitConfig{
				Enabled: true,
				Default: "8bps",
				Peers:   map[string]string{relayKey("dst-a"): "unlimited"},
			},
			sends: []send{{dst: "dst-a", frames: 15}},
			want:  map[string]int{"dst-a": 15},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			relay := newRateLimitedRelay(t, tc.limit)
			sender, _ := acceptPeer(t, relay, "sender")
			dsts := map[string]*scriptedConn{}
			ids := map[string]messages.PeerID{}
			for name := range tc.want {
				dsts[name], ids[name] = acceptPeer(t, relay, name)
			}

			for _, s := range tc.sends {
				for _, frame := range transportFrames(t, ids[s.dst], s.frames) {
					sender.deliver(t, frame)
				}
			}
			settle(t, sender, ids)

			for name, want := range tc.want {
				// The first frame on each connection is the handshake response.
				assert.Equal(t, want, len(dsts[name].frames())-1, "frames forwarded to %s", name)
			}
			assert.False(t, sender.isClosed(), "a rate-limited sender must stay connected")
		})
	}
}

func TestPeer_RateLimitDoesNotDelayOtherDestinations(t *testing.T) {
	// At 8kbps (1000 bytes per second) every frame over the budget is about 1.4s
	// short. The relay must not spend that time in the sender's read loop, where
	// it would hold back traffic to other peers and healthcheck responses.
	relay := newRateLimitedRelay(t, RateLimitConfig{
		Enabled: true,
		Peers:   map[string]string{relayKey("limited"): "8kbps"},
	})
	sender, _ := acceptPeer(t, relay, "sender")
	limited, limitedID := acceptPeer(t, relay, "limited")
	free, freeID := acceptPeer(t, relay, "free")

	for _, frame := range transportFrames(t, limitedID, 15) {
		sender.deliver(t, frame)
	}
	for _, frame := range transportFrames(t, freeID, 1) {
		sender.deliver(t, frame)
	}

	free.waitFrames(t, 2)
	assert.Less(t, len(limited.frames())-1, 15, "frames over the budget must be dropped")
	assert.False(t, sender.isClosed(), "a rate-limited sender must stay connected")
}

func relayKey(name string) string {
	return messages.HashID(name).String()
}

func newRateLimitedRelay(t *testing.T, limit RateLimitConfig) *Relay {
	t.Helper()
	relay, err := NewRelay(Config{
		ExposedAddress: "rel://127.0.0.1:1234",
		AuthValidator:  &allow.Auth{},
		RateLimit:      limit,
	})
	require.NoError(t, err)
	t.Cleanup(func() { relay.Shutdown(context.Background()) })
	return relay
}

func transportFrames(t *testing.T, dst messages.PeerID, n int) [][]byte {
	t.Helper()
	frames := make([][]byte, n)
	for i := range frames {
		frame, err := messages.MarshalTransportMsg(dst, make([]byte, 1400))
		require.NoError(t, err)
		frames[i] = frame
	}
	return frames
}

// settle returns once the relay has processed everything the sender delivered so
// far: the read loop answers a peer state subscription only after the frames
// queued before it.
func settle(t *testing.T, sender *scriptedConn, online map[string]messages.PeerID) {
	t.Helper()
	ids := make([]messages.PeerID, 0, len(online))
	for _, id := range online {
		ids = append(ids, id)
	}
	before := len(sender.frames())
	deliverSubscription(t, sender, ids)
	sender.waitFrames(t, before+1)
}
