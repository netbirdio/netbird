package manager

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"

	domainmanager "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain/manager"
	proxymanager "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy/manager"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

const validationTestCluster = "eu.proxy.test"

// withRealDomainManager swaps the stub cluster deriver for the real domain
// manager backed by the same store, so service creation is gated by the actual
// domain rows rather than by a test double that always agrees.
func withRealDomainManager(t *testing.T, mgr *Manager, testStore store.Store) {
	t.Helper()

	ctx := context.Background()
	proxyMgr, err := proxymanager.NewManager(testStore, noop.NewMeterProvider().Meter(""))
	require.NoError(t, err)

	_, err = proxyMgr.Connect(ctx, "proxy-1", "session-1", validationTestCluster, "127.0.0.1", nil, nil)
	require.NoError(t, err)

	accountMgr := &mock_server.MockAccountManager{
		StoreEventFunc: func(context.Context, string, string, string, activity.ActivityDescriber, map[string]any) {},
	}
	mgr.clusterDeriver = domainmanager.NewManager(testStore, proxyMgr, permissions.NewManager(testStore), accountMgr)
}

func newTestService(domain string) *rpservice.Service {
	return &rpservice.Service{
		Name:    "test-service",
		Domain:  domain,
		Enabled: true,
		Mode:    rpservice.ModeHTTP,
		Targets: []*rpservice.Target{{
			Host:       "10.0.0.1",
			Port:       8080,
			Protocol:   "http",
			TargetId:   testPeerID,
			TargetType: "peer",
			Enabled:    true,
		}},
	}
}

// A service must not bind to a domain the account has not validated, and
// nothing may be persisted for the attempt.
func TestCreateService_RefusesUnvalidatedDomain(t *testing.T) {
	ctx := context.Background()
	mgr, testStore := setupIntegrationTest(t)
	withRealDomainManager(t, mgr, testStore)

	_, err := testStore.CreateCustomDomain(ctx, testAccountID, "unproven.example.com", validationTestCluster, false)
	require.NoError(t, err)

	_, err = mgr.CreateService(ctx, testAccountID, testUserID, newTestService("unproven.example.com"))
	require.Error(t, err, "an unvalidated domain must not bind a service")
	assert.Contains(t, err.Error(), "not validated", "the API error should name the actual problem")

	sErr, ok := status.FromError(err)
	require.True(t, ok, "error should be a typed status error")
	assert.Equal(t, status.PreconditionFailed, sErr.Type())

	services, err := testStore.GetAccountServices(ctx, store.LockingStrengthNone, testAccountID)
	require.NoError(t, err)
	assert.Empty(t, services, "no service row should be written for a refused domain")
}

// The negative control: a validated domain still binds a service and derives
// its cluster exactly as before.
func TestCreateService_ValidatedDomainBindsService(t *testing.T) {
	ctx := context.Background()
	mgr, testStore := setupIntegrationTest(t)
	withRealDomainManager(t, mgr, testStore)

	_, err := testStore.CreateCustomDomain(ctx, testAccountID, "proven.example.com", validationTestCluster, true)
	require.NoError(t, err)

	created, err := mgr.CreateService(ctx, testAccountID, testUserID, newTestService("app.proven.example.com"))
	require.NoError(t, err)
	assert.Equal(t, validationTestCluster, created.ProxyCluster, "service should bind to the domain's target cluster")

	services, err := testStore.GetAccountServices(ctx, store.LockingStrengthNone, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1, "the service should be persisted")
	assert.Equal(t, "app.proven.example.com", services[0].Domain)
}

// An update must not be a way around the creation gate: moving a live service
// onto an unvalidated domain has to fail rather than silently keep the old
// cluster and start serving the new hostname.
func TestUpdateService_RefusesMoveToUnvalidatedDomain(t *testing.T) {
	ctx := context.Background()
	mgr, testStore := setupIntegrationTest(t)
	withRealDomainManager(t, mgr, testStore)

	_, err := testStore.CreateCustomDomain(ctx, testAccountID, "proven.example.com", validationTestCluster, true)
	require.NoError(t, err)
	_, err = testStore.CreateCustomDomain(ctx, testAccountID, "unproven.example.com", validationTestCluster, false)
	require.NoError(t, err)

	created, err := mgr.CreateService(ctx, testAccountID, testUserID, newTestService("app.proven.example.com"))
	require.NoError(t, err)

	moved := *created
	moved.Domain = "app.unproven.example.com"
	_, err = mgr.UpdateService(ctx, testAccountID, testUserID, &moved)
	require.Error(t, err, "moving to an unvalidated domain must fail")
	assert.Contains(t, err.Error(), "not validated")

	stored, err := testStore.GetServiceByID(ctx, store.LockingStrengthNone, testAccountID, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "app.proven.example.com", stored.Domain, "the service must keep its original domain")
}

func TestCreateService_DomainDeletedBeforeWrite(t *testing.T) {
	ctx := context.Background()
	mgr, testStore := setupIntegrationTest(t)
	withRealDomainManager(t, mgr, testStore)

	d, err := testStore.CreateCustomDomain(ctx, testAccountID, "proven.example.com", validationTestCluster, true)
	require.NoError(t, err)
	svc := newTestService("app.proven.example.com")
	require.NoError(t, mgr.initializeServiceForCreate(ctx, testAccountID, svc))

	// Delete after the initial authorization check, before the service transaction starts.
	require.NoError(t, testStore.DeleteCustomDomain(ctx, testAccountID, d.ID))
	err = mgr.persistNewService(ctx, testAccountID, svc)
	require.Error(t, err, "an earlier validation result must not authorize a deleted registration")
	sErr, ok := status.FromError(err)
	require.True(t, ok, "the caller must receive a typed precondition error")
	assert.Equal(t, status.PreconditionFailed, sErr.Type(), "the service must require current domain authorization")
	services, err := testStore.GetAccountServices(ctx, store.LockingStrengthNone, testAccountID)
	require.NoError(t, err)
	assert.Empty(t, services, "the failed write must not leave a service")
}

func TestUpdateService_DomainDeletedBeforeWrite(t *testing.T) {
	ctx := context.Background()
	mgr, testStore := setupIntegrationTest(t)
	withRealDomainManager(t, mgr, testStore)
	_, err := testStore.CreateCustomDomain(ctx, testAccountID, "original.example.com", validationTestCluster, true)
	require.NoError(t, err)
	d, err := testStore.CreateCustomDomain(ctx, testAccountID, "destination.example.com", validationTestCluster, true)
	require.NoError(t, err)
	svc, err := mgr.CreateService(ctx, testAccountID, testUserID, newTestService("app.original.example.com"))
	require.NoError(t, err)
	moved := svc.Copy()
	moved.Domain = "app.destination.example.com"
	cluster, err := mgr.resolveEffectiveCluster(ctx, testAccountID, moved)
	require.NoError(t, err)

	require.NoError(t, testStore.DeleteCustomDomain(ctx, testAccountID, d.ID))
	err = testStore.ExecuteInTransaction(ctx, func(tx store.Store) error {
		return mgr.executeServiceUpdate(ctx, tx, testAccountID, moved, &serviceUpdateInfo{}, nil, cluster)
	})
	require.Error(t, err, "a domain deleted after cluster resolution must reject the update")
	sErr, ok := status.FromError(err)
	require.True(t, ok, "the caller must receive a typed precondition error")
	assert.Equal(t, status.PreconditionFailed, sErr.Type(), "the move must require current domain authorization")
	stored, err := testStore.GetServiceByID(ctx, store.LockingStrengthNone, testAccountID, svc.ID)
	require.NoError(t, err)
	assert.Equal(t, svc.Domain, stored.Domain, "the service must retain its authorized domain")
}
