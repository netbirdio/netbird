package manager

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"
	"go.uber.org/mock/gomock"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	proxymanager "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy/manager"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

// setupPrivateClusterTest wires the real proxy manager as the capability
// provider and connects one proxy to testCluster reporting the given private
// capability. A nil private connects no proxy, so the capability is unreported.
func setupPrivateClusterTest(t *testing.T, private *bool) (*Manager, store.Store) {
	t.Helper()

	mgr, testStore := setupIntegrationTest(t)

	proxyMgr, err := proxymanager.NewManager(testStore, noop.NewMeterProvider().Meter(""))
	require.NoError(t, err)
	mgr.capabilities = proxyMgr

	if private != nil {
		caps := &proxy.Capabilities{Private: private}
		_, err = proxyMgr.Connect(context.Background(), "proxy-1", "session-1", testCluster, "127.0.0.1", "", nil, caps)
		require.NoError(t, err)
	}

	return mgr, testStore
}

func clusterTarget() *rpservice.Target {
	return &rpservice.Target{
		TargetId:   testCluster,
		TargetType: rpservice.TargetTypeCluster,
		Host:       "backend.lan",
		Port:       8080,
		Protocol:   "http",
		Enabled:    true,
		Options:    rpservice.TargetOptions{DirectUpstream: true},
	}
}

func directUpstreamPeerTarget() *rpservice.Target {
	return &rpservice.Target{
		TargetId:   testPeerID,
		TargetType: rpservice.TargetTypePeer,
		Host:       "backend.lan",
		Port:       8080,
		Protocol:   "http",
		Enabled:    true,
		Options:    rpservice.TargetOptions{DirectUpstream: true},
	}
}

func TestCreateService_PrivateClusterTargets(t *testing.T) {
	tests := []struct {
		name    string
		private *bool
		target  *rpservice.Target
		wantErr string
	}{
		{name: "cluster target on private cluster", private: boolPtr(true), target: clusterTarget()},
		{name: "direct upstream on private cluster", private: boolPtr(true), target: directUpstreamPeerTarget()},
		{name: "cluster target on non-private cluster", private: boolPtr(false), target: clusterTarget(), wantErr: `target_type "cluster" requires a proxy cluster with private mode enabled`},
		{name: "direct upstream on non-private cluster", private: boolPtr(false), target: directUpstreamPeerTarget(), wantErr: "direct_upstream requires a proxy cluster with private mode enabled"},
		{name: "cluster target with unreported capability", private: nil, target: clusterTarget(), wantErr: `target_type "cluster" requires a proxy cluster with private mode enabled`},
		{name: "direct upstream with unreported capability", private: nil, target: directUpstreamPeerTarget(), wantErr: "direct_upstream requires a proxy cluster with private mode enabled"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			mgr, testStore := setupPrivateClusterTest(t, tc.private)

			svc := newTestService("app.test.netbird.io")
			svc.Targets = []*rpservice.Target{tc.target}

			_, err := mgr.CreateService(ctx, testAccountID, testUserID, svc)

			services, listErr := testStore.GetAccountServices(ctx, store.LockingStrengthNone, testAccountID)
			require.NoError(t, listErr)

			if tc.wantErr == "" {
				require.NoError(t, err)
				assert.Len(t, services, 1, "the service should be persisted")
				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
			sErr, ok := status.FromError(err)
			require.True(t, ok, "the caller must receive a typed error")
			assert.Equal(t, status.InvalidArgument, sErr.Type(), "the rejection should be an invalid argument")
			assert.Empty(t, services, "a rejected service must not be persisted")
		})
	}
}

func TestCreateService_RegularTargetIgnoresPrivateCapability(t *testing.T) {
	ctx := context.Background()
	mgr, _ := setupPrivateClusterTest(t, boolPtr(false))

	_, err := mgr.CreateService(ctx, testAccountID, testUserID, newTestService("app.test.netbird.io"))
	require.NoError(t, err, "a peer target without direct upstream must not need a private cluster")
}

func TestUpdateService_PrivateClusterTargets(t *testing.T) {
	tests := []struct {
		name    string
		target  *rpservice.Target
		wantErr string
	}{
		{name: "switch to cluster target", target: clusterTarget(), wantErr: `target_type "cluster" requires a proxy cluster with private mode enabled`},
		{name: "enable direct upstream", target: directUpstreamPeerTarget(), wantErr: "direct_upstream requires a proxy cluster with private mode enabled"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			mgr, testStore := setupPrivateClusterTest(t, boolPtr(false))

			created, err := mgr.CreateService(ctx, testAccountID, testUserID, newTestService("app.test.netbird.io"))
			require.NoError(t, err)

			updated := newTestService("app.test.netbird.io")
			updated.ID = created.ID
			updated.AccountID = testAccountID
			updated.Targets = []*rpservice.Target{tc.target}

			_, err = mgr.UpdateService(ctx, testAccountID, testUserID, updated)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)

			stored, err := testStore.GetServiceByID(ctx, store.LockingStrengthNone, testAccountID, created.ID)
			require.NoError(t, err)
			require.Len(t, stored.Targets, 1)
			assert.Equal(t, rpservice.TargetTypePeer, stored.Targets[0].TargetType, "the stored target must be unchanged")
			assert.False(t, stored.Targets[0].Options.DirectUpstream, "the stored target must keep direct upstream disabled")
		})
	}
}

func TestUpdateService_PrivateClusterAllowsClusterTarget(t *testing.T) {
	ctx := context.Background()
	mgr, testStore := setupPrivateClusterTest(t, boolPtr(true))

	created, err := mgr.CreateService(ctx, testAccountID, testUserID, newTestService("app.test.netbird.io"))
	require.NoError(t, err)

	updated := newTestService("app.test.netbird.io")
	updated.ID = created.ID
	updated.AccountID = testAccountID
	updated.Targets = []*rpservice.Target{clusterTarget()}

	_, err = mgr.UpdateService(ctx, testAccountID, testUserID, updated)
	require.NoError(t, err)

	stored, err := testStore.GetServiceByID(ctx, store.LockingStrengthNone, testAccountID, created.ID)
	require.NoError(t, err)
	require.Len(t, stored.Targets, 1)
	assert.Equal(t, rpservice.TargetTypeCluster, stored.Targets[0].TargetType, "the cluster target should be stored")
}

func TestValidatePrivateClusterTargets_NoLookupWithoutPrivateTargets(t *testing.T) {
	ctrl := gomock.NewController(t)
	// No ClusterSupportsPrivate expectation: a lookup would fail the test.
	mgr := &Manager{capabilities: proxy.NewMockManager(ctrl)}

	targets := []*rpservice.Target{{TargetId: testPeerID, TargetType: rpservice.TargetTypePeer}}
	require.NoError(t, mgr.validatePrivateClusterTargets(context.Background(), targets, testCluster))
}
