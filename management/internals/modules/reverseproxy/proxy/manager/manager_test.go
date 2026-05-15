package manager

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
)

type mockStore struct {
	saveProxyFunc                              func(ctx context.Context, p *proxy.Proxy) error
	disconnectProxyFunc                        func(ctx context.Context, proxyID, sessionID string) error
	updateProxyHeartbeatFunc                   func(ctx context.Context, p *proxy.Proxy) error
	getActiveProxyClusterAddressesFunc         func(ctx context.Context) ([]string, error)
	getActiveProxyClusterAddressesForAccFunc   func(ctx context.Context, accountID string) ([]string, error)
	cleanupStaleProxiesFunc                    func(ctx context.Context, d time.Duration) error
	getProxyByAccountIDFunc                    func(ctx context.Context, accountID string) (*proxy.Proxy, error)
	countProxiesByAccountIDFunc                func(ctx context.Context, accountID string) (int64, error)
	isClusterAddressConflictingFunc            func(ctx context.Context, clusterAddress, accountID string) (bool, error)
	deleteAccountClusterFunc                   func(ctx context.Context, clusterAddress, accountID string) error
}

func (m *mockStore) SaveProxy(ctx context.Context, p *proxy.Proxy) error {
	if m.saveProxyFunc != nil {
		return m.saveProxyFunc(ctx, p)
	}
	return nil
}
func (m *mockStore) DisconnectProxy(ctx context.Context, proxyID, sessionID string) error {
	if m.disconnectProxyFunc != nil {
		return m.disconnectProxyFunc(ctx, proxyID, sessionID)
	}
	return nil
}
func (m *mockStore) UpdateProxyHeartbeat(ctx context.Context, p *proxy.Proxy) error {
	if m.updateProxyHeartbeatFunc != nil {
		return m.updateProxyHeartbeatFunc(ctx, p)
	}
	return nil
}
func (m *mockStore) GetActiveProxyClusterAddresses(ctx context.Context) ([]string, error) {
	if m.getActiveProxyClusterAddressesFunc != nil {
		return m.getActiveProxyClusterAddressesFunc(ctx)
	}
	return nil, nil
}
func (m *mockStore) GetActiveProxyClusterAddressesForAccount(ctx context.Context, accountID string) ([]string, error) {
	if m.getActiveProxyClusterAddressesForAccFunc != nil {
		return m.getActiveProxyClusterAddressesForAccFunc(ctx, accountID)
	}
	return nil, nil
}
func (m *mockStore) GetActiveProxyClusters(_ context.Context, _ string) ([]proxy.Cluster, error) {
	return nil, nil
}
func (m *mockStore) CleanupStaleProxies(ctx context.Context, d time.Duration) error {
	if m.cleanupStaleProxiesFunc != nil {
		return m.cleanupStaleProxiesFunc(ctx, d)
	}
	return nil
}
func (m *mockStore) GetProxyByAccountID(ctx context.Context, accountID string) (*proxy.Proxy, error) {
	if m.getProxyByAccountIDFunc != nil {
		return m.getProxyByAccountIDFunc(ctx, accountID)
	}
	return nil, fmt.Errorf("proxy not found for account %s", accountID)
}
func (m *mockStore) CountProxiesByAccountID(ctx context.Context, accountID string) (int64, error) {
	if m.countProxiesByAccountIDFunc != nil {
		return m.countProxiesByAccountIDFunc(ctx, accountID)
	}
	return 0, nil
}
func (m *mockStore) IsClusterAddressConflicting(ctx context.Context, clusterAddress, accountID string) (bool, error) {
	if m.isClusterAddressConflictingFunc != nil {
		return m.isClusterAddressConflictingFunc(ctx, clusterAddress, accountID)
	}
	return false, nil
}
func (m *mockStore) DeleteAccountCluster(ctx context.Context, clusterAddress, accountID string) error {
	if m.deleteAccountClusterFunc != nil {
		return m.deleteAccountClusterFunc(ctx, clusterAddress, accountID)
	}
	return nil
}
func (m *mockStore) GetClusterSupportsCustomPorts(_ context.Context, _ string) *bool {
	return nil
}
func (m *mockStore) GetClusterRequireSubdomain(_ context.Context, _ string) *bool {
	return nil
}
func (m *mockStore) GetClusterSupportsCrowdSec(_ context.Context, _ string) *bool {
	return nil
}

func newTestManager(s store) *Manager {
	meter := noop.NewMeterProvider().Meter("test")
	m, err := NewManager(s, meter)
	if err != nil {
		panic(err)
	}
	return m
}

func TestConnect_WithAccountID(t *testing.T) {
	accountID := "acc-123"

	var savedProxy *proxy.Proxy
	s := &mockStore{
		saveProxyFunc: func(_ context.Context, p *proxy.Proxy) error {
			savedProxy = p
			return nil
		},
	}

	mgr := newTestManager(s)
	_, err := mgr.Connect(context.Background(), "proxy-1", "session-1", "cluster.example.com", "10.0.0.1", &accountID, nil)
	require.NoError(t, err)

	require.NotNil(t, savedProxy)
	assert.Equal(t, "proxy-1", savedProxy.ID)
	assert.Equal(t, "session-1", savedProxy.SessionID)
	assert.Equal(t, "cluster.example.com", savedProxy.ClusterAddress)
	assert.Equal(t, "10.0.0.1", savedProxy.IPAddress)
	assert.Equal(t, &accountID, savedProxy.AccountID)
	assert.Equal(t, proxy.StatusConnected, savedProxy.Status)
	assert.NotNil(t, savedProxy.ConnectedAt)
}

func TestConnect_WithoutAccountID(t *testing.T) {
	var savedProxy *proxy.Proxy
	s := &mockStore{
		saveProxyFunc: func(_ context.Context, p *proxy.Proxy) error {
			savedProxy = p
			return nil
		},
	}

	mgr := newTestManager(s)
	_, err := mgr.Connect(context.Background(), "proxy-1", "session-1", "eu.proxy.netbird.io", "10.0.0.1", nil, nil)
	require.NoError(t, err)

	require.NotNil(t, savedProxy)
	assert.Nil(t, savedProxy.AccountID)
	assert.Equal(t, proxy.StatusConnected, savedProxy.Status)
}

func TestConnect_StoreError(t *testing.T) {
	s := &mockStore{
		saveProxyFunc: func(_ context.Context, _ *proxy.Proxy) error {
			return errors.New("db error")
		},
	}

	mgr := newTestManager(s)
	_, err := mgr.Connect(context.Background(), "proxy-1", "session-1", "cluster.example.com", "10.0.0.1", nil, nil)
	assert.Error(t, err)
}

func TestIsClusterAddressAvailable(t *testing.T) {
	tests := []struct {
		name        string
		conflicting bool
		storeErr    error
		wantResult  bool
		wantErr     bool
	}{
		{
			name:        "available - no conflict",
			conflicting: false,
			wantResult:  true,
		},
		{
			name:        "not available - conflict exists",
			conflicting: true,
			wantResult:  false,
		},
		{
			name:     "store error",
			storeErr: errors.New("db error"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &mockStore{
				isClusterAddressConflictingFunc: func(_ context.Context, _, _ string) (bool, error) {
					return tt.conflicting, tt.storeErr
				},
			}

			mgr := newTestManager(s)
			result, err := mgr.IsClusterAddressAvailable(context.Background(), "cluster.example.com", "acc-123")
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantResult, result)
		})
	}
}

func TestCountAccountProxies(t *testing.T) {
	tests := []struct {
		name      string
		count     int64
		storeErr  error
		wantCount int64
		wantErr   bool
	}{
		{
			name:      "no proxies",
			count:     0,
			wantCount: 0,
		},
		{
			name:      "one proxy",
			count:     1,
			wantCount: 1,
		},
		{
			name:     "store error",
			storeErr: errors.New("db error"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &mockStore{
				countProxiesByAccountIDFunc: func(_ context.Context, _ string) (int64, error) {
					return tt.count, tt.storeErr
				},
			}

			mgr := newTestManager(s)
			count, err := mgr.CountAccountProxies(context.Background(), "acc-123")
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantCount, count)
		})
	}
}

func TestGetAccountProxy(t *testing.T) {
	accountID := "acc-123"

	t.Run("found", func(t *testing.T) {
		expected := &proxy.Proxy{
			ID:             "proxy-1",
			ClusterAddress: "byop.example.com",
			AccountID:      &accountID,
			Status:         proxy.StatusConnected,
		}
		s := &mockStore{
			getProxyByAccountIDFunc: func(_ context.Context, accID string) (*proxy.Proxy, error) {
				assert.Equal(t, accountID, accID)
				return expected, nil
			},
		}

		mgr := newTestManager(s)
		p, err := mgr.GetAccountProxy(context.Background(), accountID)
		require.NoError(t, err)
		assert.Equal(t, expected, p)
	})

	t.Run("not found", func(t *testing.T) {
		s := &mockStore{
			getProxyByAccountIDFunc: func(_ context.Context, _ string) (*proxy.Proxy, error) {
				return nil, errors.New("not found")
			},
		}

		mgr := newTestManager(s)
		_, err := mgr.GetAccountProxy(context.Background(), accountID)
		assert.Error(t, err)
	})
}

func TestDeleteAccountCluster(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var deletedCluster, deletedAccount string
		s := &mockStore{
			deleteAccountClusterFunc: func(_ context.Context, clusterAddress, accountID string) error {
				deletedCluster = clusterAddress
				deletedAccount = accountID
				return nil
			},
		}

		mgr := newTestManager(s)
		err := mgr.DeleteAccountCluster(context.Background(), "cluster.example.com", "acc-123")
		require.NoError(t, err)
		assert.Equal(t, "cluster.example.com", deletedCluster)
		assert.Equal(t, "acc-123", deletedAccount)
	})

	t.Run("store error", func(t *testing.T) {
		s := &mockStore{
			deleteAccountClusterFunc: func(_ context.Context, _, _ string) error {
				return errors.New("db error")
			},
		}

		mgr := newTestManager(s)
		err := mgr.DeleteAccountCluster(context.Background(), "cluster.example.com", "acc-123")
		assert.Error(t, err)
	})
}

func TestGetActiveClusterAddressesForAccount(t *testing.T) {
	expected := []string{"byop.example.com"}
	s := &mockStore{
		getActiveProxyClusterAddressesForAccFunc: func(_ context.Context, accID string) ([]string, error) {
			assert.Equal(t, "acc-123", accID)
			return expected, nil
		},
	}

	mgr := newTestManager(s)
	result, err := mgr.GetActiveClusterAddressesForAccount(context.Background(), "acc-123")
	require.NoError(t, err)
	assert.Equal(t, expected, result)
}
