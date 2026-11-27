package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/peerauth"
)

// Relay ids and WireGuard public keys both end in base64 padding. The two
// fixtures identify different peers.
const (
	testRelayID = "sha-zuRnNsLpGxC5615kqmkL42BOUMCZhiXs/HJ59Yihp30="
	testPubKey  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)

func TestParseRateLimitPeers(t *testing.T) {
	tests := []struct {
		name    string
		entries []string
		want    map[string]string
		wantErr bool
	}{
		{
			name:    "keys keep their padding",
			entries: []string{testRelayID + "=10mbps", testPubKey + "=20mbps"},
			want:    map[string]string{testRelayID: "10mbps", testPubKey: "20mbps"},
		},
		{name: "missing rate", entries: []string{testRelayID}, wantErr: true},
		{name: "missing peer", entries: []string{"=10mbps"}, wantErr: true},
		{name: "no separator", entries: []string{"10mbps"}, wantErr: true},
		{name: "repeated peer", entries: []string{testPubKey + "=10mbps", testPubKey + "=unlimited"}, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseRateLimitPeers(tc.entries)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got, "parsed per-peer limits")
		})
	}
}

// The relay checks legacy tokens with the auth secret until the flag day, when
// --peer-auth-required replaces it: exactly one of the two is set.
func TestConfigValidate_AuthSecretOrRequired(t *testing.T) {
	for name, tc := range map[string]struct {
		secret   string
		required bool
		wantErr  bool
	}{
		"auth secret":        {secret: "relay-secret"},
		"peer auth required": {required: true},
		"both":               {secret: "relay-secret", required: true, wantErr: true},
		"neither":            {wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := Config{ExposedAddress: "rels://relay.example.com:443", AuthSecret: tc.secret, PeerAuthRequired: tc.required}
			err := cfg.Validate()
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestRateLimitPeersFlag(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("rate-limit-peers")
	require.NotNil(t, flag, "the flag must be registered")

	// The flag is shared package state and may already hold NB_RATE_LIMIT_PEERS from
	// the environment, so parse into a fresh flag of the same kind.
	var peers []string
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.StringSliceVar(&peers, flag.Name, nil, "")
	require.Equal(t, flag.Value.Type(), fs.Lookup(flag.Name).Value.Type(), "the test flag must mirror the registered one")

	// NB_RATE_LIMIT_PEERS goes through the same Set call.
	require.NoError(t, fs.Set(flag.Name, testRelayID+"=10mbps,"+testPubKey+"=20mbps"))

	got, err := parseRateLimitPeers(peers)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{testRelayID: "10mbps", testPubKey: "20mbps"}, got,
		"comma-separated entries must reach the relay with their keys intact")
}

func TestPeerAuthTokenKeys(t *testing.T) {
	t.Run("no public keys", func(t *testing.T) {
		keys, err := peerAuthTokenKeys(&Config{AuthSecret: "relay-secret"})
		require.NoError(t, err)
		assert.Empty(t, keys.Ed25519, "without public keys no bound token may verify, whatever the auth secret")
	})

	t.Run("public keys", func(t *testing.T) {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		keys, err := peerAuthTokenKeys(&Config{PeerAuthPublicKeys: []string{base64.StdEncoding.EncodeToString(pub)}})
		require.NoError(t, err)
		require.NoError(t, keys.Validate())
		assert.Equal(t, pub, keys.Ed25519[peerauth.Ed25519KeyID(pub)], "the configured key must verify bound tokens")
	})

	t.Run("malformed public key", func(t *testing.T) {
		_, err := peerAuthTokenKeys(&Config{PeerAuthPublicKeys: []string{"bm90LWEta2V5"}})
		assert.Error(t, err, "a malformed public key must fail startup")
	})
}
