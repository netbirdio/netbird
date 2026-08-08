package manager

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"

	domainmanager "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain/manager"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
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
	domainMgr := domainmanager.NewManager(testStore, proxyMgr, permissions.NewManager(testStore), accountMgr)
	mgr.clusterDeriver = domainMgr
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

// A service must not bind to a domain the account never proved it owns, and
// nothing may be persisted for the attempt.
func TestCreateService_RefusesUnvalidatedDomain(t *testing.T) {
	ctx := context.Background()
	mgr, testStore := setupIntegrationTest(t)
	withRealDomainManager(t, mgr, testStore)

	_, err := testStore.CreateCustomDomain(ctx, testAccountID, "unproven.example.com", validationTestCluster, false, time.Now().UTC())
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

	_, err := testStore.CreateCustomDomain(ctx, testAccountID, "proven.example.com", validationTestCluster, true, time.Now().UTC())
	require.NoError(t, err)

	created, err := mgr.CreateService(ctx, testAccountID, testUserID, newTestService("app.proven.example.com"))
	require.NoError(t, err)
	assert.Equal(t, validationTestCluster, created.ProxyCluster, "service should bind to the domain's target cluster")

	services, err := testStore.GetAccountServices(ctx, store.LockingStrengthNone, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1, "the service should be persisted")
	assert.Equal(t, "app.proven.example.com", services[0].Domain)
}

// The mapping the proxy receives carries management's verdict, so the proxy can
// refuse the route on its own if this gate is ever regressed.
func TestProtoMapping_CarriesDomainValidation(t *testing.T) {
	ctx := context.Background()
	mgr, testStore := setupIntegrationTest(t)
	withRealDomainManager(t, mgr, testStore)

	_, err := testStore.CreateCustomDomain(ctx, testAccountID, "proven.example.com", validationTestCluster, true, time.Now().UTC())
	require.NoError(t, err)
	_, err = testStore.CreateCustomDomain(ctx, testAccountID, "unproven.example.com", validationTestCluster, false, time.Now().UTC())
	require.NoError(t, err)

	validated := newTestService("proven.example.com")
	validated.AccountID = testAccountID
	mapping := mgr.protoMapping(ctx, rpservice.Create, validated, proxy.OIDCValidationConfig{})
	assert.True(t, mapping.GetDomainValidated(), "a validated domain should be advertised as such")

	unvalidated := newTestService("unproven.example.com")
	unvalidated.AccountID = testAccountID
	mapping = mgr.protoMapping(ctx, rpservice.Create, unvalidated, proxy.OIDCValidationConfig{})
	assert.False(t, mapping.GetDomainValidated(), "an unvalidated domain must be advertised as unvalidated")

	free := newTestService("myapp.abc123." + validationTestCluster)
	free.AccountID = testAccountID
	mapping = mgr.protoMapping(ctx, rpservice.Create, free, proxy.OIDCValidationConfig{})
	assert.True(t, mapping.GetDomainValidated(), "free cluster domains need no ownership proof")
}

// Without a cluster deriver there is nothing that can answer the ownership
// question, so the mapping must be advertised as unvalidated.
func TestProtoMapping_DeniesWithoutClusterDeriver(t *testing.T) {
	mgr := &Manager{}

	svc := newTestService("apps.example.com")
	svc.AccountID = testAccountID

	mapping := mgr.protoMapping(context.Background(), rpservice.Create, svc, proxy.OIDCValidationConfig{})
	assert.False(t, mapping.GetDomainValidated())
}

// An update must not be a way around the creation gate: moving a live service
// onto an unvalidated domain has to fail rather than silently keep the old
// cluster and start serving the new hostname.
func TestUpdateService_RefusesMoveToUnvalidatedDomain(t *testing.T) {
	ctx := context.Background()
	mgr, testStore := setupIntegrationTest(t)
	withRealDomainManager(t, mgr, testStore)

	_, err := testStore.CreateCustomDomain(ctx, testAccountID, "proven.example.com", validationTestCluster, true, time.Now().UTC())
	require.NoError(t, err)
	_, err = testStore.CreateCustomDomain(ctx, testAccountID, "unproven.example.com", validationTestCluster, false, time.Now().UTC())
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
