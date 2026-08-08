package manager

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

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

// stubResolver answers CNAME lookups from a table the test controls, so DNS
// state can change between calls without touching a real resolver.
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

func (r *stubResolver) remove(host string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.cnames, host)
}

// fakeClock drives claim expiry without sleeping.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type domainTestEnv struct {
	manager  Manager
	store    nbstore.Store
	resolver *stubResolver
	clock    *fakeClock
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
	clock := &fakeClock{now: time.Now().UTC()}

	mgr := Manager{
		store:              testStore,
		proxyManager:       proxyMgr,
		validator:          domain.Validator{Resolver: resolver},
		permissionsManager: permissions.NewManager(testStore),
		accountManager: &mock_server.MockAccountManager{
			StoreEventFunc: func(context.Context, string, string, string, activity.ActivityDescriber, map[string]any) {},
		},
		now:               clock.Now,
		revalidationFails: &failureTracker{counts: make(map[string]int)},
	}

	return &domainTestEnv{manager: mgr, store: testStore, resolver: resolver, clock: clock}
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

// A domain whose CNAME check fails must be stored unvalidated and must not be
// usable to derive a proxy cluster, which is what service creation gates on.
func TestCreateDomain_FailedLookupIsNotServable(t *testing.T) {
	ctx := context.Background()
	env := setupDomainTest(t)

	created, err := env.manager.CreateDomain(ctx, accountA, accountAUser, "apps.example.com", testCluster)
	require.NoError(t, err)
	assert.False(t, created.Validated, "a domain whose CNAME lookup fails must not be created validated")

	stored := storedDomain(t, env.store, accountA, "apps.example.com")
	require.NotNil(t, stored, "domain row should exist")
	assert.False(t, stored.Validated, "persisted row must be unvalidated")
	assert.False(t, stored.ClaimedAt.IsZero(), "claim must be dated so it can expire")

	cluster, err := env.manager.DeriveClusterFromDomain(ctx, accountA, "apps.example.com")
	require.Error(t, err, "an unvalidated domain must not resolve a cluster")
	assert.Empty(t, cluster)
	assert.Contains(t, err.Error(), "not validated", "error should tell the caller what to fix")

	sErr, ok := status.FromError(err)
	require.True(t, ok, "error should be a typed status error")
	assert.Equal(t, status.PreconditionFailed, sErr.Type())

	assert.False(t, env.manager.IsDomainValidated(ctx, accountA, "apps.example.com"))
	assert.False(t, env.manager.IsDomainValidated(ctx, accountA, "sub.apps.example.com"),
		"subdomains of an unvalidated custom domain are not servable either")
}

// Two accounts may both request a name nobody has proven they own. The second
// request must be an ordinary success, never a database-level failure.
func TestCreateDomain_UnvalidatedClaimDoesNotBlockOtherAccounts(t *testing.T) {
	ctx := context.Background()
	env := setupDomainTest(t)

	_, err := env.manager.CreateDomain(ctx, accountA, accountAUser, "shared.example.com", testCluster)
	require.NoError(t, err)

	second, err := env.manager.CreateDomain(ctx, accountB, accountBUser, "shared.example.com", testCluster)
	require.NoError(t, err, "an unvalidated claim by another account must not block the request")
	assert.False(t, second.Validated)

	assert.NotNil(t, storedDomain(t, env.store, accountA, "shared.example.com"))
	assert.NotNil(t, storedDomain(t, env.store, accountB, "shared.example.com"))
}

// Once an account serves a name, another account asking for it gets a clean
// conflict that says nothing about who holds it.
func TestCreateDomain_ValidatedDomainConflictsForOtherAccounts(t *testing.T) {
	ctx := context.Background()
	env := setupDomainTest(t)
	env.resolver.set("validation.owned.example.com", testCluster)

	first, err := env.manager.CreateDomain(ctx, accountA, accountAUser, "owned.example.com", testCluster)
	require.NoError(t, err)
	require.True(t, first.Validated, "matching CNAME should validate on create")

	_, err = env.manager.CreateDomain(ctx, accountB, accountBUser, "owned.example.com", testCluster)
	require.Error(t, err)

	sErr, ok := status.FromError(err)
	require.True(t, ok, "conflict must be a typed status error, not a raw database error")
	assert.Equal(t, status.AlreadyExists, sErr.Type(), "conflict should map to 409, not 500")
	assert.NotContains(t, sErr.Message, accountA, "the response must not reveal the holding account")

	assert.Nil(t, storedDomain(t, env.store, accountB, "owned.example.com"), "no row should be written on conflict")
}

// Re-requesting a domain the account already holds is a conflict too.
func TestCreateDomain_SameAccountDuplicateConflicts(t *testing.T) {
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

// The negative control: a domain that genuinely validates still derives its
// cluster exactly as before.
func TestCreateDomain_ValidatedDomainDerivesCluster(t *testing.T) {
	ctx := context.Background()
	env := setupDomainTest(t)
	env.resolver.set("validation.valid.example.com", testCluster)

	created, err := env.manager.CreateDomain(ctx, accountA, accountAUser, "valid.example.com", testCluster)
	require.NoError(t, err)
	require.True(t, created.Validated)

	cluster, err := env.manager.DeriveClusterFromDomain(ctx, accountA, "valid.example.com")
	require.NoError(t, err)
	assert.Equal(t, testCluster, cluster)

	cluster, err = env.manager.DeriveClusterFromDomain(ctx, accountA, "app.valid.example.com")
	require.NoError(t, err, "subdomains of a validated custom domain resolve too")
	assert.Equal(t, testCluster, cluster)

	assert.True(t, env.manager.IsDomainValidated(ctx, accountA, "valid.example.com"))
}

// Free cluster domains never need a custom domain row.
func TestIsDomainValidated_FreeDomain(t *testing.T) {
	ctx := context.Background()
	env := setupDomainTest(t)

	assert.True(t, env.manager.IsDomainValidated(ctx, accountA, "myapp.abc123."+testCluster))
	assert.False(t, env.manager.IsDomainValidated(ctx, accountA, "myapp.unknown.test"))
}

// An account that never proves control loses the name after claimTTL, freeing
// it instead of parking it forever.
func TestRunMaintenance_EvictsExpiredClaim(t *testing.T) {
	ctx := context.Background()
	env := setupDomainTest(t)

	_, err := env.manager.CreateDomain(ctx, accountA, accountAUser, "stale.example.com", testCluster)
	require.NoError(t, err)

	env.clock.advance(claimTTL - time.Minute)
	env.manager.RunMaintenance(ctx)
	assert.NotNil(t, storedDomain(t, env.store, accountA, "stale.example.com"),
		"claim must survive while it is still inside the window")

	env.clock.advance(2 * time.Minute)
	env.manager.RunMaintenance(ctx)
	assert.Nil(t, storedDomain(t, env.store, accountA, "stale.example.com"),
		"claim must be evicted once it has outlived the window")
}

// A validated domain is never evicted, however old the claim.
func TestRunMaintenance_KeepsValidatedDomain(t *testing.T) {
	ctx := context.Background()
	env := setupDomainTest(t)
	env.resolver.set("validation.live.example.com", testCluster)

	_, err := env.manager.CreateDomain(ctx, accountA, accountAUser, "live.example.com", testCluster)
	require.NoError(t, err)

	env.clock.advance(30 * 24 * time.Hour)
	env.manager.RunMaintenance(ctx)

	stored := storedDomain(t, env.store, accountA, "live.example.com")
	require.NotNil(t, stored, "a validated domain must not be evicted")
	assert.True(t, stored.Validated)
}

// Moving DNS away flips the domain back to unvalidated and restarts its claim
// window, so the name eventually becomes available again.
func TestRunMaintenance_RevalidationFlipsAndThenEvicts(t *testing.T) {
	ctx := context.Background()
	env := setupDomainTest(t)
	env.resolver.set("validation.moved.example.com", testCluster)

	_, err := env.manager.CreateDomain(ctx, accountA, accountAUser, "moved.example.com", testCluster)
	require.NoError(t, err)
	require.True(t, storedDomain(t, env.store, accountA, "moved.example.com").Validated)

	env.resolver.remove("validation.moved.example.com")

	// A single failed lookup is treated as a transient resolver problem.
	env.manager.RunMaintenance(ctx)
	assert.True(t, storedDomain(t, env.store, accountA, "moved.example.com").Validated,
		"one failed lookup must not unvalidate a live domain")

	for i := 1; i < revalidationFailureThreshold; i++ {
		env.manager.RunMaintenance(ctx)
	}

	flipped := storedDomain(t, env.store, accountA, "moved.example.com")
	require.NotNil(t, flipped)
	assert.False(t, flipped.Validated, "repeated failures must unvalidate the domain")
	assert.Equal(t, env.clock.Now(), flipped.ClaimedAt.UTC(), "the claim window restarts on the flip")

	_, err = env.manager.DeriveClusterFromDomain(ctx, accountA, "moved.example.com")
	assert.Error(t, err, "an unvalidated domain stops resolving a cluster")

	env.clock.advance(claimTTL + time.Minute)
	env.manager.RunMaintenance(ctx)
	assert.Nil(t, storedDomain(t, env.store, accountA, "moved.example.com"),
		"the flipped claim expires like any other unvalidated claim")
}

// DNS coming back before the threshold clears the failure history.
func TestRunMaintenance_RecoveredLookupResetsFailures(t *testing.T) {
	ctx := context.Background()
	env := setupDomainTest(t)
	env.resolver.set("validation.flaky.example.com", testCluster)

	_, err := env.manager.CreateDomain(ctx, accountA, accountAUser, "flaky.example.com", testCluster)
	require.NoError(t, err)

	env.resolver.remove("validation.flaky.example.com")
	for i := 1; i < revalidationFailureThreshold; i++ {
		env.manager.RunMaintenance(ctx)
	}

	env.resolver.set("validation.flaky.example.com", testCluster)
	for i := 0; i < revalidationFailureThreshold; i++ {
		env.manager.RunMaintenance(ctx)
	}

	stored := storedDomain(t, env.store, accountA, "flaky.example.com")
	require.NotNil(t, stored)
	assert.True(t, stored.Validated, "a recovered lookup must not carry stale failure counts")
}

// A validated domain another account already serves cannot be taken over, even
// when the second account's CNAME check passes: the check proves zone control,
// not who asked.
func TestValidateDomain_DoesNotStealValidatedDomain(t *testing.T) {
	ctx := context.Background()
	env := setupDomainTest(t)

	_, err := env.manager.CreateDomain(ctx, accountB, accountBUser, "contested.example.com", testCluster)
	require.NoError(t, err)

	env.resolver.set("validation.contested.example.com", testCluster)
	first, err := env.manager.CreateDomain(ctx, accountA, accountAUser, "contested.example.com", testCluster)
	require.NoError(t, err)
	require.True(t, first.Validated)

	claim := storedDomain(t, env.store, accountB, "contested.example.com")
	require.NotNil(t, claim)
	env.manager.ValidateDomain(ctx, accountB, accountBUser, claim.ID)

	assert.False(t, storedDomain(t, env.store, accountB, "contested.example.com").Validated,
		"the late claimant must not validate a name another account already serves")
	assert.True(t, storedDomain(t, env.store, accountA, "contested.example.com").Validated)
}

// Domains are bounded per account: every one of them becomes an ACME order
// against an issuance rate limit shared with every other account on the cluster.
func TestCreateDomain_EnforcesPerAccountQuota(t *testing.T) {
	ctx := context.Background()
	env := setupDomainTest(t)

	for i := 0; i < maxCustomDomainsPerAccount; i++ {
		_, err := env.manager.CreateDomain(ctx, accountA, accountAUser, fmt.Sprintf("app-%d.example.com", i), testCluster)
		require.NoError(t, err)
	}

	_, err := env.manager.CreateDomain(ctx, accountA, accountAUser, "one-too-many.example.com", testCluster)
	require.Error(t, err)

	sErr, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, status.PreconditionFailed, sErr.Type())

	_, err = env.manager.CreateDomain(ctx, accountB, accountBUser, "other-account.example.com", testCluster)
	assert.NoError(t, err, "the quota is per account")
}
