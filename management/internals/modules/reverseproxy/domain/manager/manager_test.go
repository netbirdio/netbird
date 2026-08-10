package manager

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

	mgr := Manager{proxyManager: pm}
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

	mgr := Manager{proxyManager: pm}
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

	mgr := Manager{proxyManager: pm}
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

	mgr := Manager{proxyManager: pm}
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

	mgr := Manager{proxyManager: pm}
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

	mgr := Manager{proxyManager: pm}
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

	mgr := Manager{proxyManager: pm}
	result, err := mgr.getClusterAllowList(context.Background(), "acc-123")
	require.NoError(t, err)
	assert.Equal(t, []string{"byop.example.com"}, result)
}
