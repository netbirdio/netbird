package affectedpeers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/store"
)

// fakeProxyStore implements only the two store methods loadProxyServices calls;
// the embedded nil store.Store panics if anything else is invoked, which keeps
// the test honest about the surface under test.
type fakeProxyStore struct {
	store.Store
	proxyByCluster map[string][]string
	persisted      []*rpservice.Service
}

func (f *fakeProxyStore) GetEmbeddedProxyPeerIDsByCluster(_ context.Context, _ string) (map[string][]string, error) {
	return f.proxyByCluster, nil
}

func (f *fakeProxyStore) GetAccountServices(_ context.Context, _ store.LockingStrength, _ string) ([]*rpservice.Service, error) {
	return f.persisted, nil
}

func serviceIDs(svcs []*rpservice.Service) []string {
	ids := make([]string, 0, len(svcs))
	for _, s := range svcs {
		ids = append(ids, s.ID)
	}
	return ids
}

// loadProxyServices must merge the synthesised agent-network services (which are
// never persisted) with the persisted ones, so the proxy-affected expansion can
// see agent-network AccessGroups. Without this the embedded proxy peer is never
// flagged on a client group change and only a full resync (restart) recovers.
func TestLoadProxyServices_MergesSynthesizedAgentNetworkServices(t *testing.T) {
	prev := agentNetworkSynthesizer
	t.Cleanup(func() { agentNetworkSynthesizer = prev })
	SetAgentNetworkSynthesizer(func(_ context.Context, _ store.Store, _ string) ([]*rpservice.Service, error) {
		return []*rpservice.Service{
			{ID: "agent-net-svc-acc", ProxyCluster: "proxy.netbird.local", Private: true, AccessGroups: []string{"gB"}},
		}, nil
	})

	s := &fakeProxyStore{
		proxyByCluster: map[string][]string{"proxy.netbird.local": {"proxy-peer-1"}},
		persisted:      []*rpservice.Service{{ID: "persisted-rp-svc", ProxyCluster: "proxy.netbird.local"}},
	}
	snap := &Snapshot{}
	require.NoError(t, snap.loadProxyServices(context.Background(), s, "acc"))

	ids := serviceIDs(snap.services)
	assert.Contains(t, ids, "persisted-rp-svc", "persisted services must be kept")
	assert.Contains(t, ids, "agent-net-svc-acc", "synthesised agent-network service must be merged in")
}

// With no synthesiser registered, loadProxyServices falls back to persisted
// services only (no panic, no behaviour change for non-agent-network builds).
func TestLoadProxyServices_NoSynthesizerRegistered(t *testing.T) {
	prev := agentNetworkSynthesizer
	t.Cleanup(func() { agentNetworkSynthesizer = prev })
	agentNetworkSynthesizer = nil

	s := &fakeProxyStore{
		proxyByCluster: map[string][]string{"c": {"proxy-1"}},
		persisted:      []*rpservice.Service{{ID: "persisted"}},
	}
	snap := &Snapshot{}
	require.NoError(t, snap.loadProxyServices(context.Background(), s, "acc"))
	assert.Equal(t, []string{"persisted"}, serviceIDs(snap.services))
}

// No embedded proxy peers → skip entirely (don't even call the synthesiser).
func TestLoadProxyServices_NoEmbeddedProxyPeersSkips(t *testing.T) {
	prev := agentNetworkSynthesizer
	t.Cleanup(func() { agentNetworkSynthesizer = prev })
	called := false
	SetAgentNetworkSynthesizer(func(_ context.Context, _ store.Store, _ string) ([]*rpservice.Service, error) {
		called = true
		return nil, nil
	})

	s := &fakeProxyStore{proxyByCluster: map[string][]string{}}
	snap := &Snapshot{}
	require.NoError(t, snap.loadProxyServices(context.Background(), s, "acc"))
	assert.False(t, called, "synthesiser must not run for accounts without embedded proxy peers")
	assert.Empty(t, snap.services)
}
