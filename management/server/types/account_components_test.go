package types_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
)

func TestGetPeerNetworkMapComponents_PeerMissingFromAccount(t *testing.T) {
	account, validatedPeers := scalableTestAccount(3, 1)

	components := account.GetPeerNetworkMapComponents(
		context.Background(),
		"peer-that-does-not-exist",
		nbdns.CustomZone{},
		nil,
		validatedPeers,
		account.GetResourcePoliciesMap(),
		account.GetResourceRoutersMap(),
		nil,
	)

	require.NotNil(t, components)
	assert.True(t, components.IsEmpty(), "a missing peer must produce empty components")
	require.NotNil(t, components.Network, "the account Network floor still applies")

	for id, p := range components.Peers {
		require.NotNil(t, p, "components.Peers[%q] is nil; the encoder would panic on it", id)
	}
	assert.Nil(t, components.GetPeerInfo("peer-that-does-not-exist"),
		"there is no peer to carry when it is absent from the account")
}
