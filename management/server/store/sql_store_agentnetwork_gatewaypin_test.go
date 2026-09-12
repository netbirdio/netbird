package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	agentNetworkTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
)

// TestHasGatewayPinnedByOtherAccount_RealStore drives the query a proxy
// registration asks before claiming a cluster address, against a real sqlite
// store.
//
// A gateway pin is a claim on the host: it is immutable, it is served by
// whichever proxy declares that address, and an account-scoped proxy only ever
// receives its own account's mappings — so a proxy from a different account
// taking the address strands the pin. The account's own pin is the opposite
// case and must stay claimable, because pinning first and deploying the proxy
// after is the documented order.
func TestHasGatewayPinnedByOtherAccount_RealStore(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	defer cleanup()

	const (
		pinnedHost = "gw.account1.example.com"
		freeHost   = "nobody.example.com"
	)

	settings := agentNetworkTypes.DefaultSettings("account1")
	settings.Domain = pinnedHost
	settings.ProxyAddress = pinnedHost
	require.NoError(t, s.CreateAgentNetworkSettings(ctx, settings), "seeding the pin must succeed")

	t.Run("another account is refused the host", func(t *testing.T) {
		pinned, err := s.HasGatewayPinnedByOtherAccount(ctx, pinnedHost, "account2")
		require.NoError(t, err)
		assert.True(t, pinned, "a host another account pinned its gateway to is claimed")
	})

	t.Run("the pinning account may still claim it", func(t *testing.T) {
		pinned, err := s.HasGatewayPinnedByOtherAccount(ctx, pinnedHost, "account1")
		require.NoError(t, err)
		assert.False(t, pinned, "an account must be able to deploy the proxy for its own pin")
	})

	t.Run("an unpinned host is free", func(t *testing.T) {
		pinned, err := s.HasGatewayPinnedByOtherAccount(ctx, freeHost, "account2")
		require.NoError(t, err)
		assert.False(t, pinned, "a host no gateway is pinned to stays claimable")
	})

	t.Run("a labeled pin claims the cluster, not just the endpoint", func(t *testing.T) {
		// A labeled bootstrap hangs <label>.<cluster> beneath the address while
		// pinning the cluster itself, so the claim follows proxy_address.
		labeled := agentNetworkTypes.DefaultSettings("account3")
		labeled.ProxyAddress = "byop.account3.example.com"
		labeled.Domain = "violet." + labeled.ProxyAddress
		require.NoError(t, s.CreateAgentNetworkSettings(ctx, labeled))

		pinned, err := s.HasGatewayPinnedByOtherAccount(ctx, labeled.ProxyAddress, "account2")
		require.NoError(t, err)
		assert.True(t, pinned, "the pinned cluster address is the claim, not the labeled endpoint")

		pinned, err = s.HasGatewayPinnedByOtherAccount(ctx, labeled.Domain, "account2")
		require.NoError(t, err)
		assert.False(t, pinned, "the labeled endpoint itself is not a cluster claim")
	})
}
