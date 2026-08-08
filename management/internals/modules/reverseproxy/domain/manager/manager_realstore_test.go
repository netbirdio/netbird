package manager

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/domain"
	proxymanager "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy/manager"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/mock_server"
	"github.com/netbirdio/netbird/management/server/permissions"
	nbstore "github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	testCluster  = "eu.proxy.test"
	accountA     = "account-a"
	accountAUser = "account-a-admin"
	accountB     = "account-b"
	accountBUser = "account-b-admin"
)

// stubResolver answers CNAME lookups from a table the test controls, so a
// domain can point at the cluster or nowhere without touching a real resolver.
type stubResolver struct {
	mu     sync.Mutex
	cnames map[string]string
}

func (r *stubResolver) LookupCNAME(_ context.Context, host string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	cname, ok := r.cnames[host]
	if !ok {
		return "", fmt.Errorf("lookup %s: no such host", host)
	}
	return cname + ".", nil
}

func (r *stubResolver) set(host, cname string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cnames[host] = cname
}

type domainTestEnv struct {
	manager  Manager
	store    nbstore.Store
	resolver *stubResolver
}

// setupDomainTest builds the domain manager on a real SQLite store with two
// accounts and one active public proxy cluster.
func setupDomainTest(t *testing.T) *domainTestEnv {
	t.Helper()

	ctx := context.Background()
	testStore, cleanup, err := nbstore.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)

	for accountID, userID := range map[string]string{accountA: accountAUser, accountB: accountBUser} {
		require.NoError(t, testStore.SaveAccount(ctx, &types.Account{
			Id:        accountID,
			CreatedBy: userID,
			Settings:  &types.Settings{},
			Users: map[string]*types.User{
				userID: {
					Id:        userID,
					AccountID: accountID,
					Role:      types.UserRoleAdmin,
				},
			},
		}))
	}

	proxyMgr, err := proxymanager.NewManager(testStore, noop.NewMeterProvider().Meter(""))
	require.NoError(t, err)

	_, err = proxyMgr.Connect(ctx, "proxy-1", "session-1", testCluster, "127.0.0.1", nil, nil)
	require.NoError(t, err)

	resolver := &stubResolver{cnames: make(map[string]string)}

	mgr := Manager{
		store:              testStore,
		proxyManager:       proxyMgr,
		validator:          domain.Validator{Resolver: resolver},
		permissionsManager: permissions.NewManager(testStore),
		accountManager: &mock_server.MockAccountManager{
			StoreEventFunc: func(context.Context, string, string, string, activity.ActivityDescriber, map[string]any) {},
		},
	}

	return &domainTestEnv{manager: mgr, store: testStore, resolver: resolver}
}

// storedDomain reads a domain row back through the store so assertions are made
// on what was persisted rather than on the value the manager returned.
func storedDomain(t *testing.T, s nbstore.Store, accountID, domainName string) *domain.Domain {
	t.Helper()

	domains, err := s.ListCustomDomains(context.Background(), accountID)
	require.NoError(t, err)
	for _, d := range domains {
		if d.Domain == domainName {
			return d
		}
	}
	return nil
}

// A domain whose CNAME check fails is stored unvalidated and must not resolve a
// cluster, which is what service creation gates on.
func TestCreateDomain_FailedLookupIsNotServable(t *testing.T) {
	ctx := context.Background()
	env := setupDomainTest(t)

	created, err := env.manager.CreateDomain(ctx, accountA, accountAUser, "apps.example.com", testCluster)
	require.NoError(t, err)
	assert.False(t, created.Validated, "a domain whose CNAME lookup fails must not be created validated")

	stored := storedDomain(t, env.store, accountA, "apps.example.com")
	require.NotNil(t, stored, "domain row should exist")
	assert.False(t, stored.Validated, "persisted row must be unvalidated")

	cluster, err := env.manager.DeriveClusterFromDomain(ctx, accountA, "apps.example.com")
	require.Error(t, err, "an unvalidated domain must not resolve a cluster")
	assert.Empty(t, cluster)
	assert.Contains(t, err.Error(), "not validated", "error should tell the caller what to fix")

	sErr, ok := status.FromError(err)
	require.True(t, ok, "error should be a typed status error")
	assert.Equal(t, status.PreconditionFailed, sErr.Type())

	_, err = env.manager.DeriveClusterFromDomain(ctx, accountA, "sub.apps.example.com")
	assert.Error(t, err, "subdomains of an unvalidated custom domain are not servable either")
}

// A second account claiming a registered domain gets a clean conflict, not a
// database error surfaced as a 500.
func TestCreateDomain_DuplicateIsAConflict(t *testing.T) {
	ctx := context.Background()
	env := setupDomainTest(t)

	_, err := env.manager.CreateDomain(ctx, accountA, accountAUser, "shared.example.com", testCluster)
	require.NoError(t, err)

	_, err = env.manager.CreateDomain(ctx, accountB, accountBUser, "shared.example.com", testCluster)
	require.Error(t, err)

	sErr, ok := status.FromError(err)
	require.True(t, ok, "conflict must be a typed status error, not a raw database error")
	assert.Equal(t, status.AlreadyExists, sErr.Type(), "conflict should map to 409, not 500")
	assert.NotContains(t, sErr.Message, accountA, "the response must not reveal the holding account")

	assert.Nil(t, storedDomain(t, env.store, accountB, "shared.example.com"), "no row should be written on conflict")
}

// The same account re-adding one of its own domains is a conflict too.
func TestCreateDomain_SameAccountDuplicateIsAConflict(t *testing.T) {
	ctx := context.Background()
	env := setupDomainTest(t)

	_, err := env.manager.CreateDomain(ctx, accountA, accountAUser, "dup.example.com", testCluster)
	require.NoError(t, err)

	_, err = env.manager.CreateDomain(ctx, accountA, accountAUser, "dup.example.com", testCluster)
	require.Error(t, err)

	sErr, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, status.AlreadyExists, sErr.Type())
}

// The negative control: a validated domain still derives its cluster, for the
// bare name and for subdomains, exactly as before.
func TestCreateDomain_ValidatedDomainDerivesCluster(t *testing.T) {
	ctx := context.Background()
	env := setupDomainTest(t)
	env.resolver.set("validation.valid.example.com", testCluster)

	created, err := env.manager.CreateDomain(ctx, accountA, accountAUser, "valid.example.com", testCluster)
	require.NoError(t, err)
	require.True(t, created.Validated, "a matching CNAME should validate on create")

	cluster, err := env.manager.DeriveClusterFromDomain(ctx, accountA, "valid.example.com")
	require.NoError(t, err)
	assert.Equal(t, testCluster, cluster)

	cluster, err = env.manager.DeriveClusterFromDomain(ctx, accountA, "app.valid.example.com")
	require.NoError(t, err)
	assert.Equal(t, testCluster, cluster, "subdomains of a validated custom domain resolve too")
}

// Validating a domain flips the gate: the same lookup that failed before now
// resolves a cluster.
func TestValidateDomain_UnlocksClusterDerivation(t *testing.T) {
	ctx := context.Background()
	env := setupDomainTest(t)

	created, err := env.manager.CreateDomain(ctx, accountA, accountAUser, "later.example.com", testCluster)
	require.NoError(t, err)
	require.False(t, created.Validated)

	_, err = env.manager.DeriveClusterFromDomain(ctx, accountA, "later.example.com")
	require.Error(t, err)

	env.resolver.set("validation.later.example.com", testCluster)
	env.manager.ValidateDomain(ctx, accountA, accountAUser, created.ID)

	require.True(t, storedDomain(t, env.store, accountA, "later.example.com").Validated)

	cluster, err := env.manager.DeriveClusterFromDomain(ctx, accountA, "later.example.com")
	require.NoError(t, err)
	assert.Equal(t, testCluster, cluster)
}

// Free cluster domains are unaffected by the custom domain gate.
func TestDeriveClusterFromDomain_FreeDomainUnaffected(t *testing.T) {
	ctx := context.Background()
	env := setupDomainTest(t)

	cluster, err := env.manager.DeriveClusterFromDomain(ctx, accountA, "myapp.abc123."+testCluster)
	require.NoError(t, err)
	assert.Equal(t, testCluster, cluster)
}

// The manager pre-check exists to turn a conflict into a 409, but the unique
// index on the column is what actually guarantees the domain is claimed once.
func TestStore_DuplicateDomainRejectedByIndex(t *testing.T) {
	ctx := context.Background()
	env := setupDomainTest(t)

	_, err := env.store.CreateCustomDomain(ctx, accountA, "indexed.example.com", testCluster, false)
	require.NoError(t, err)

	_, err = env.store.CreateCustomDomain(ctx, accountB, "indexed.example.com", testCluster, false)
	assert.Error(t, err, "the unique index must reject the same domain in a second account")
}
