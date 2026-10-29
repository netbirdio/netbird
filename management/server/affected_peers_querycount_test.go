package server

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/affectedpeers"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
)

// countingStore wraps a real store and counts the per-account collection loads
// the resolver performs, so a test can assert each is read at most once and that
// irrelevant collections are skipped entirely.
type countingStore struct {
	store.Store
	mu     sync.Mutex
	counts map[string]int
}

func newCountingStore(s store.Store) *countingStore {
	return &countingStore{Store: s, counts: map[string]int{}}
}

func (c *countingStore) bump(name string) {
	c.mu.Lock()
	c.counts[name]++
	c.mu.Unlock()
}

func (c *countingStore) count(name string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counts[name]
}

func (c *countingStore) total() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, v := range c.counts {
		n += v
	}
	return n
}

func (c *countingStore) GetAccountPolicies(ctx context.Context, ls store.LockingStrength, accountID string) ([]*types.Policy, error) {
	c.bump("policies")
	return c.Store.GetAccountPolicies(ctx, ls, accountID)
}

func (c *countingStore) GetAccountRoutes(ctx context.Context, ls store.LockingStrength, accountID string) ([]*route.Route, error) {
	c.bump("routes")
	return c.Store.GetAccountRoutes(ctx, ls, accountID)
}

func (c *countingStore) GetAccountNameServerGroups(ctx context.Context, ls store.LockingStrength, accountID string) ([]*nbdns.NameServerGroup, error) {
	c.bump("nameservers")
	return c.Store.GetAccountNameServerGroups(ctx, ls, accountID)
}

func (c *countingStore) GetAccountDNSSettings(ctx context.Context, ls store.LockingStrength, accountID string) (*types.DNSSettings, error) {
	c.bump("dnssettings")
	return c.Store.GetAccountDNSSettings(ctx, ls, accountID)
}

func (c *countingStore) GetNetworkRoutersByAccountID(ctx context.Context, ls store.LockingStrength, accountID string) ([]*routerTypes.NetworkRouter, error) {
	c.bump("routers")
	return c.Store.GetNetworkRoutersByAccountID(ctx, ls, accountID)
}

func (c *countingStore) GetNetworkResourcesByAccountID(ctx context.Context, ls store.LockingStrength, accountID string) ([]*resourceTypes.NetworkResource, error) {
	c.bump("resources")
	return c.Store.GetNetworkResourcesByAccountID(ctx, ls, accountID)
}

func (c *countingStore) GetAccountServices(ctx context.Context, ls store.LockingStrength, accountID string) ([]*rpservice.Service, error) {
	c.bump("services")
	return c.Store.GetAccountServices(ctx, ls, accountID)
}

// TestAffectedPeers_QueryCount_NoRedundantFullTableLoads asserts the resolver
// loads each per-account collection at most once per Resolve (memoization) even
// on a change that drives every bridge, and skips the services table when the
// account has no embedded proxy peers.
func TestAffectedPeers_QueryCount_NoRedundantFullTableLoads(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	_, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID), true)
	require.NoError(t, err)

	cs := newCountingStore(s.manager.Store)

	// A group change that exercises policies, routers, resources and the bridge.
	change := affectedpeers.Change{ChangedGroupIDs: []string{s.sourceGroupID}}
	snap, err := affectedpeers.Load(ctx, cs, s.accountID, change)
	require.NoError(t, err)
	affected := snap.Expand(ctx, s.accountID, change)
	assert.Contains(t, affected, s.routerPeerID, "bridge must still resolve the routing peer")

	for _, name := range []string{"policies", "routes", "nameservers", "dnssettings", "routers", "resources"} {
		assert.LessOrEqualf(t, cs.count(name), 1,
			"%s must be loaded at most once per Resolve, got %d", name, cs.count(name))
	}
	assert.Equal(t, 0, cs.count("services"),
		"services must not be loaded when the account has no embedded proxy peers")
}

// TestAffectedPeers_QueryCount_NarrowChangeSkipsLoads asserts that a change with
// no group/peer signal touches no per-account collections beyond what its inputs
// require.
func TestAffectedPeers_QueryCount_NarrowChangeSkipsLoads(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	cs := newCountingStore(s.manager.Store)

	// A bare network change drives only the router->source bridge: routers and
	// resources are needed, but routes/nameservers/dnssettings/services are not.
	_, err := affectedpeers.Load(ctx, cs, s.accountID, affectedpeers.Change{Networks: []*networkTypes.Network{{ID: s.networkID}}})
	require.NoError(t, err)

	assert.Equal(t, 0, cs.count("routes"), "routes must not be loaded for a network-only change")
	assert.Equal(t, 0, cs.count("nameservers"), "nameservers must not be loaded for a network-only change")
	assert.Equal(t, 0, cs.count("dnssettings"), "dnssettings must not be loaded for a network-only change")
	assert.Equal(t, 0, cs.count("services"), "services must not be loaded for a network-only change")
}

// TestAffectedPeers_QueryCount_ExpandReadsNothing is the core invariant of the
// Load/Expand split: Load (run inside the transaction) does all store reads;
// Expand (run after commit) must touch the store ZERO times, so it never holds
// the write lock and never reads post-commit state.
func TestAffectedPeers_QueryCount_ExpandReadsNothing(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	_, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID), true)
	require.NoError(t, err)

	change := affectedpeers.Change{ChangedGroupIDs: []string{s.sourceGroupID}}

	cs := newCountingStore(s.manager.Store)
	snap, err := affectedpeers.Load(ctx, cs, s.accountID, change)
	require.NoError(t, err)
	require.Greater(t, cs.total(), 0, "Load must read the store")

	// Any store access during Expand would increment the same counter. Expand
	// operates purely on the snapshot, so the count must not move.
	readsAfterLoad := cs.total()
	affected := snap.Expand(ctx, s.accountID, change)
	assert.Contains(t, affected, s.routerPeerID, "Expand must still produce the affected peers from the snapshot")
	assert.Equal(t, readsAfterLoad, cs.total(), "Expand must perform zero store reads — it operates purely on the loaded snapshot")
}
