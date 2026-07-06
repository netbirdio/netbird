package internal

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	firewallManager "github.com/netbirdio/netbird/client/firewall/manager"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// TestToExcludedLazyPeers_ForwardTarget guards a regression: AllowedIPs arrive as
// CIDR (a peer's overlay IP is a /32), so comparing them for equality against
// ForwardRule.TranslatedAddress.String() (unmasked) never matched and the
// forward-target peer was never excluded from lazy connections.
func TestToExcludedLazyPeers_ForwardTarget(t *testing.T) {
	e := &Engine{}

	const targetPeerKey = "target-peer"
	peers := []*mgmProto.RemotePeerConfig{
		{WgPubKey: targetPeerKey, AllowedIps: []string{"100.110.8.145/32"}},
		{WgPubKey: "other-peer", AllowedIps: []string{"100.110.9.10/32"}},
	}
	rules := []firewallManager.ForwardRule{
		{TranslatedAddress: netip.MustParseAddr("100.110.8.145")},
	}

	excluded := e.toExcludedLazyPeers(rules, peers)

	require.True(t, excluded[targetPeerKey], "forward-target peer must be excluded from lazy connections")
	require.False(t, excluded["other-peer"], "non-target peer must not be excluded")
	require.Len(t, excluded, 1)
}

func TestToExcludedLazyPeers_NoRules(t *testing.T) {
	e := &Engine{}

	peers := []*mgmProto.RemotePeerConfig{
		{WgPubKey: "peer-a", AllowedIps: []string{"100.110.8.145/32"}},
	}

	excluded := e.toExcludedLazyPeers(nil, peers)
	require.Empty(t, excluded)
}
