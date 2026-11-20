package cmd

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
