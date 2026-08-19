package manager

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	agentnetworkTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain"
	nbstore "github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

func TestExtractClusterFromCustomDomains(t *testing.T) {
	tests := map[string]struct {
		host          string
		customDomains []*domain.Domain
		wantCluster   string
		wantOK        bool
	}{
		"exact non-wildcard match": {
			host: "example.com",
			customDomains: []*domain.Domain{
				{Domain: "example.com", TargetCluster: "cluster-a"},
			},
			wantCluster: "cluster-a",
			wantOK:      true,
		},
		"wildcard matches subdomain": {
			host: "app.example.com",
			customDomains: []*domain.Domain{
				{Domain: "*.example.com", TargetCluster: "cluster-a"},
			},
			wantCluster: "cluster-a",
			wantOK:      true,
		},
		"wildcard matches apex": {
			host: "example.com",
			customDomains: []*domain.Domain{
				{Domain: "*.example.com", TargetCluster: "cluster-a"},
			},
			wantCluster: "cluster-a",
			wantOK:      true,
		},
		"non-wildcard matches subdomain": {
			host: "app.example.com",
			customDomains: []*domain.Domain{
				{Domain: "example.com", TargetCluster: "cluster-a"},
			},
			wantCluster: "cluster-a",
			wantOK:      true,
		},
		"exact non-wildcard beats wildcard": {
			host: "example.com",
			customDomains: []*domain.Domain{
				{Domain: "*.example.com", TargetCluster: "cluster-wild"},
				{Domain: "example.com", TargetCluster: "cluster-exact"},
			},
			wantCluster: "cluster-exact",
			wantOK:      true,
		},
		"longest wildcard suffix wins": {
			host: "app.sub.example.com",
			customDomains: []*domain.Domain{
				{Domain: "*.example.com", TargetCluster: "cluster-short"},
				{Domain: "*.sub.example.com", TargetCluster: "cluster-long"},
			},
			wantCluster: "cluster-long",
			wantOK:      true,
		},
		"longest non-wildcard suffix wins": {
			host: "app.sub.example.com",
			customDomains: []*domain.Domain{
				{Domain: "example.com", TargetCluster: "cluster-short"},
				{Domain: "sub.example.com", TargetCluster: "cluster-long"},
			},
			wantCluster: "cluster-long",
			wantOK:      true,
		},
		"trailing dot on host is normalized": {
			host: "example.com.",
			customDomains: []*domain.Domain{
				{Domain: "example.com", TargetCluster: "cluster-a"},
			},
			wantCluster: "cluster-a",
			wantOK:      true,
		},
		"trailing dot on custom domain is normalized": {
			host: "example.com",
			customDomains: []*domain.Domain{
				{Domain: "example.com.", TargetCluster: "cluster-a"},
			},
			wantCluster: "cluster-a",
			wantOK:      true,
		},
		"case insensitive match": {
			host: "APP.Example.COM",
			customDomains: []*domain.Domain{
				{Domain: "*.example.com", TargetCluster: "cluster-a"},
			},
			wantCluster: "cluster-a",
			wantOK:      true,
		},
		"no match returns false": {
			host: "other.com",
			customDomains: []*domain.Domain{
				{Domain: "example.com", TargetCluster: "cluster-a"},
				{Domain: "*.example.com", TargetCluster: "cluster-b"},
			},
			wantCluster: "",
			wantOK:      false,
		},
		"empty custom domains returns false": {
			host:          "example.com",
			customDomains: nil,
			wantCluster:   "",
			wantOK:        false,
		},
		"partial suffix does not match": {
			host: "notexample.com",
			customDomains: []*domain.Domain{
				{Domain: "example.com", TargetCluster: "cluster-a"},
			},
			wantCluster: "",
			wantOK:      false,
		},
		"wildcard does not match partial suffix": {
			host: "notexample.com",
			customDomains: []*domain.Domain{
				{Domain: "*.example.com", TargetCluster: "cluster-a"},
			},
			wantCluster: "",
			wantOK:      false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cluster, ok := extractClusterFromCustomDomains(tc.host, tc.customDomains)
			if ok != tc.wantOK {
				t.Errorf("ok: got %v, want %v", ok, tc.wantOK)
			}
			if cluster != tc.wantCluster {
				t.Errorf("cluster: got %q, want %q", cluster, tc.wantCluster)
			}
		})
	}
}

type mockProxyManager struct {
	getActiveClusterAddressesFunc           func(ctx context.Context) ([]string, error)
	getActiveClusterAddressesForAccountFunc func(ctx context.Context, accountID string) ([]string, error)
}

func (m *mockProxyManager) GetActiveClusterAddresses(ctx context.Context) ([]string, error) {
	if m.getActiveClusterAddressesFunc != nil {
		return m.getActiveClusterAddressesFunc(ctx)
	}
	return nil, nil
}

func (m *mockProxyManager) GetActiveClusterAddressesForAccount(ctx context.Context, accountID string) ([]string, error) {
	if m.getActiveClusterAddressesForAccountFunc != nil {
		return m.getActiveClusterAddressesForAccountFunc(ctx, accountID)
	}
	return nil, nil
}

func (m *mockProxyManager) ClusterSupportsCustomPorts(_ context.Context, _ string) *bool {
	return nil
}

func (m *mockProxyManager) ClusterRequireSubdomain(_ context.Context, _ string) *bool {
	return nil
}

func (m *mockProxyManager) ClusterSupportsCrowdSec(_ context.Context, _ string) *bool {
	return nil
}

func (m *mockProxyManager) ClusterSupportsPrivate(_ context.Context, _ string) *bool {
	return nil
}

func TestGetClusterAllowList_BYOPMergedWithPublic(t *testing.T) {
	pm := &mockProxyManager{
		getActiveClusterAddressesForAccountFunc: func(_ context.Context, accID string) ([]string, error) {
			assert.Equal(t, "acc-123", accID)
			return []string{"byop.example.com"}, nil
		},
		getActiveClusterAddressesFunc: func(_ context.Context) ([]string, error) {
			return []string{"eu.proxy.netbird.io"}, nil
		},
	}

	mgr := Manager{store: &stubStore{}, proxyManager: pm}
	result, err := mgr.getClusterAllowList(context.Background(), "acc-123")
	require.NoError(t, err)
	assert.Equal(t, []string{"byop.example.com", "eu.proxy.netbird.io"}, result)
}

func TestGetClusterAllowList_DeduplicatesBYOPAndPublic(t *testing.T) {
	pm := &mockProxyManager{
		getActiveClusterAddressesForAccountFunc: func(_ context.Context, _ string) ([]string, error) {
			return []string{"shared.example.com", "byop.example.com"}, nil
		},
		getActiveClusterAddressesFunc: func(_ context.Context) ([]string, error) {
			return []string{"shared.example.com", "eu.proxy.netbird.io"}, nil
		},
	}

	mgr := Manager{store: &stubStore{}, proxyManager: pm}
	result, err := mgr.getClusterAllowList(context.Background(), "acc-123")
	require.NoError(t, err)
	assert.Equal(t, []string{"shared.example.com", "byop.example.com", "eu.proxy.netbird.io"}, result)
}

func TestGetClusterAllowList_NoBYOP_FallbackToShared(t *testing.T) {
	pm := &mockProxyManager{
		getActiveClusterAddressesForAccountFunc: func(_ context.Context, _ string) ([]string, error) {
			return nil, nil
		},
		getActiveClusterAddressesFunc: func(_ context.Context) ([]string, error) {
			return []string{"eu.proxy.netbird.io", "us.proxy.netbird.io"}, nil
		},
	}

	mgr := Manager{store: &stubStore{}, proxyManager: pm}
	result, err := mgr.getClusterAllowList(context.Background(), "acc-123")
	require.NoError(t, err)
	assert.Equal(t, []string{"eu.proxy.netbird.io", "us.proxy.netbird.io"}, result)
}

func TestGetClusterAllowList_BYOPError_ReturnsError(t *testing.T) {
	pm := &mockProxyManager{
		getActiveClusterAddressesForAccountFunc: func(_ context.Context, _ string) ([]string, error) {
			return nil, errors.New("db error")
		},
	}

	mgr := Manager{store: &stubStore{}, proxyManager: pm}
	result, err := mgr.getClusterAllowList(context.Background(), "acc-123")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "BYOP cluster addresses")
}

func TestGetClusterAllowList_PublicError_ReturnsError(t *testing.T) {
	pm := &mockProxyManager{
		getActiveClusterAddressesForAccountFunc: func(_ context.Context, _ string) ([]string, error) {
			return []string{"byop.example.com"}, nil
		},
		getActiveClusterAddressesFunc: func(_ context.Context) ([]string, error) {
			return nil, errors.New("db error")
		},
	}

	mgr := Manager{store: &stubStore{}, proxyManager: pm}
	result, err := mgr.getClusterAllowList(context.Background(), "acc-123")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "public cluster addresses")
}

func TestGetClusterAllowList_BYOPEmptySlice_FallbackToShared(t *testing.T) {
	pm := &mockProxyManager{
		getActiveClusterAddressesForAccountFunc: func(_ context.Context, _ string) ([]string, error) {
			return []string{}, nil
		},
		getActiveClusterAddressesFunc: func(_ context.Context) ([]string, error) {
			return []string{"eu.proxy.netbird.io"}, nil
		},
	}

	mgr := Manager{store: &stubStore{}, proxyManager: pm}
	result, err := mgr.getClusterAllowList(context.Background(), "acc-123")
	require.NoError(t, err)
	assert.Equal(t, []string{"eu.proxy.netbird.io"}, result)
}

func TestGetClusterAllowList_PublicEmpty_BYOPOnly(t *testing.T) {
	pm := &mockProxyManager{
		getActiveClusterAddressesForAccountFunc: func(_ context.Context, _ string) ([]string, error) {
			return []string{"byop.example.com"}, nil
		},
		getActiveClusterAddressesFunc: func(_ context.Context) ([]string, error) {
			return nil, nil
		},
	}

	mgr := Manager{store: &stubStore{}, proxyManager: pm}
	result, err := mgr.getClusterAllowList(context.Background(), "acc-123")
	require.NoError(t, err)
	assert.Equal(t, []string{"byop.example.com"}, result)
}

// stubStore satisfies the manager's narrow store interface for allow-list
// tests. Only the agent-network settings lookup participates; the default (a
// nil func) reads as "no settings row", the state most accounts are in.
type stubStore struct {
	getAgentNetworkSettingsFunc func(ctx context.Context, accountID string) (*agentnetworkTypes.Settings, error)
}

func (s *stubStore) GetAccount(context.Context, string) (*types.Account, error) {
	panic("not used in allow-list tests")
}

func (s *stubStore) GetAgentNetworkSettings(ctx context.Context, _ nbstore.LockingStrength, accountID string) (*agentnetworkTypes.Settings, error) {
	if s.getAgentNetworkSettingsFunc != nil {
		return s.getAgentNetworkSettingsFunc(ctx, accountID)
	}
	return nil, status.Errorf(status.NotFound, "agent network settings for account %s not found", accountID)
}

func (s *stubStore) GetCustomDomain(context.Context, string, string) (*domain.Domain, error) {
	panic("not used in allow-list tests")
}

func (s *stubStore) ListFreeDomains(context.Context, string) ([]string, error) {
	panic("not used in allow-list tests")
}

func (s *stubStore) ListCustomDomains(context.Context, string) ([]*domain.Domain, error) {
	panic("not used in allow-list tests")
}

func (s *stubStore) CreateCustomDomain(context.Context, string, string, string, bool) (*domain.Domain, error) {
	panic("not used in allow-list tests")
}

func (s *stubStore) UpdateCustomDomain(context.Context, string, *domain.Domain) (*domain.Domain, error) {
	panic("not used in allow-list tests")
}

func (s *stubStore) DeleteCustomDomain(context.Context, string, string) error {
	panic("not used in allow-list tests")
}

// TestGetClusterAllowList_DedicatedGatewayAddressExcluded pins invariant (B)'s
// chokepoint: a self-addressed settings pin reserves the account's gateway
// address, so it is dropped from the allow list — which, because the
// free-domain suffix match is depth-independent, rejects every name beneath
// it as well as the bare one. Other addresses are unaffected.
func TestGetClusterAllowList_DedicatedGatewayAddressExcluded(t *testing.T) {
	pm := &mockProxyManager{
		getActiveClusterAddressesForAccountFunc: func(_ context.Context, _ string) ([]string, error) {
			return []string{"brave-otter.gateway.example.com", "byop.example.com"}, nil
		},
		getActiveClusterAddressesFunc: func(_ context.Context) ([]string, error) {
			return []string{"eu.proxy.netbird.io"}, nil
		},
	}
	st := &stubStore{
		getAgentNetworkSettingsFunc: func(_ context.Context, accountID string) (*agentnetworkTypes.Settings, error) {
			assert.Equal(t, "acc-123", accountID,
				"the exclusion must look up the requesting account's own settings")
			return &agentnetworkTypes.Settings{
				AccountID:    accountID,
				Domain:       "brave-otter.gateway.example.com",
				ProxyAddress: "brave-otter.gateway.example.com",
			}, nil
		},
	}

	mgr := Manager{store: st, proxyManager: pm}
	result, err := mgr.getClusterAllowList(context.Background(), "acc-123")
	require.NoError(t, err)
	assert.Equal(t, []string{"byop.example.com", "eu.proxy.netbird.io"}, result,
		"the dedicated gateway address must be reserved from cluster selection")
}

// TestGetClusterAllowList_LabeledPinDoesNotExclude pins the counterpart: a
// labeled pin means the gateway rides on a shared cluster serving ordinary
// services too, so nothing is reserved.
func TestGetClusterAllowList_LabeledPinDoesNotExclude(t *testing.T) {
	pm := &mockProxyManager{
		getActiveClusterAddressesForAccountFunc: func(_ context.Context, _ string) ([]string, error) {
			return []string{"byop.example.com"}, nil
		},
		getActiveClusterAddressesFunc: func(_ context.Context) ([]string, error) {
			return []string{"eu.proxy.netbird.io"}, nil
		},
	}
	st := &stubStore{
		getAgentNetworkSettingsFunc: func(_ context.Context, accountID string) (*agentnetworkTypes.Settings, error) {
			return &agentnetworkTypes.Settings{
				AccountID:    accountID,
				Domain:       "violet.eu.proxy.netbird.io",
				ProxyAddress: "eu.proxy.netbird.io",
			}, nil
		},
	}

	mgr := Manager{store: st, proxyManager: pm}
	result, err := mgr.getClusterAllowList(context.Background(), "acc-123")
	require.NoError(t, err)
	assert.Equal(t, []string{"byop.example.com", "eu.proxy.netbird.io"}, result,
		"a labeled pin reserves nothing")
}

// TestGetClusterAllowList_SettingsLookupError_ReturnsError pins that a store
// outage is surfaced rather than silently treated as "nothing reserved" —
// failing open here would offer a reserved gateway address for ordinary
// services.
func TestGetClusterAllowList_SettingsLookupError_ReturnsError(t *testing.T) {
	pm := &mockProxyManager{
		getActiveClusterAddressesForAccountFunc: func(_ context.Context, _ string) ([]string, error) {
			return []string{"byop.example.com"}, nil
		},
		getActiveClusterAddressesFunc: func(_ context.Context) ([]string, error) {
			return []string{"eu.proxy.netbird.io"}, nil
		},
	}
	st := &stubStore{
		getAgentNetworkSettingsFunc: func(_ context.Context, _ string) (*agentnetworkTypes.Settings, error) {
			return nil, status.Errorf(status.Internal, "store outage")
		},
	}

	mgr := Manager{store: st, proxyManager: pm}
	result, err := mgr.getClusterAllowList(context.Background(), "acc-123")
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "agent network settings")
}
