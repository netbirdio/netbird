package internal

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	firewallManager "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/peerstore"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

func TestPrefixesContain(t *testing.T) {
	tests := []struct {
		name     string
		prefixes []string
		addr     string
		want     bool
	}{
		{name: "own overlay /32 matches", prefixes: []string{"100.110.8.145/32"}, addr: "100.110.8.145", want: true},
		{name: "addr inside routed subnet", prefixes: []string{"10.121.0.0/16"}, addr: "10.121.208.4", want: true},
		{name: "addr outside subnet", prefixes: []string{"10.121.0.0/16"}, addr: "10.122.0.1", want: false},
		{name: "different /32", prefixes: []string{"100.110.8.145/32"}, addr: "100.110.8.146", want: false},
		{name: "ipv6 /128 matches", prefixes: []string{"fd00::1/128"}, addr: "fd00::1", want: true},
		{name: "no prefixes", prefixes: nil, addr: "10.121.208.4", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefixes := make([]netip.Prefix, 0, len(tt.prefixes))
			for _, p := range tt.prefixes {
				prefixes = append(prefixes, netip.MustParsePrefix(p))
			}
			require.Equal(t, tt.want, prefixesContain(prefixes, netip.MustParseAddr(tt.addr)))
		})
	}
}

// TestToExcludedLazyPeers_ForwardTarget guards a regression: the forward-target
// peer (the peer routing a ForwardRule.TranslatedAddress) must be excluded from
// lazy connections, matched via the peer's already-parsed AllowedIPs.
func TestToExcludedLazyPeers_ForwardTarget(t *testing.T) {
	const targetPeerKey = "cccccccccccccccccccccccccccccccccccccccccc0="
	const otherPeerKey = "dddddddddddddddddddddddddddddddddddddddddd0="

	store := peerstore.NewConnStore()
	store.AddPeerConn(targetPeerKey, newTestConn(t, targetPeerKey, "100.110.8.145/32"))
	store.AddPeerConn(otherPeerKey, newTestConn(t, otherPeerKey, "100.110.9.10/32"))

	// Lazy on for normal peers, so the only exclusion under test is the forward target.
	e := &Engine{peerStore: store, connMgr: &ConnMgr{force: lazyForceOn}}

	peers := []*mgmProto.RemotePeerConfig{
		{WgPubKey: targetPeerKey, AllowedIps: []string{"100.110.8.145/32"}},
		{WgPubKey: otherPeerKey, AllowedIps: []string{"100.110.9.10/32"}},
	}
	rules := []firewallManager.ForwardRule{
		{TranslatedAddress: netip.MustParseAddr("100.110.8.145")},
	}

	excluded := e.toExcludedLazyPeers(rules, peers)

	require.True(t, excluded[targetPeerKey], "forward-target peer must be excluded from lazy connections")
	require.False(t, excluded[otherPeerKey], "non-target peer must not be excluded")
	require.Len(t, excluded, 1)
}

func TestToExcludedLazyPeers_NoRules(t *testing.T) {
	// Lazy on for normal peers and no forward rules, so nothing is excluded.
	e := &Engine{peerStore: peerstore.NewConnStore(), connMgr: &ConnMgr{force: lazyForceOn}}

	peers := []*mgmProto.RemotePeerConfig{
		{WgPubKey: "peer-a", AllowedIps: []string{"100.110.8.145/32"}},
	}

	require.Empty(t, e.toExcludedLazyPeers(nil, peers))
}

func newTestConn(t *testing.T, key, allowedIP string) *peer.Conn {
	t.Helper()
	conn, err := peer.NewConn(peer.ConnConfig{
		Key:      key,
		WgConfig: peer.WgConfig{AllowedIps: []netip.Prefix{netip.MustParsePrefix(allowedIP)}},
	}, peer.ServiceDependencies{})
	require.NoError(t, err)
	return conn
}
