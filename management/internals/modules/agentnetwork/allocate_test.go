package agentnetwork

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"runtime"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/labelgen"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/server/store"
	nbtypes "github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

// TestIsUniqueConstraintError_RecognisesAllThreeDialects — the allocator's
// retry loop hinges on this. A missed dialect turns a retryable collision into
// a hard provider-create failure.
func TestIsUniqueConstraintError_RecognisesAllThreeDialects(t *testing.T) {
	for name, err := range map[string]error{
		"postgres": errors.New(`ERROR: duplicate key value violates unique constraint (SQLSTATE 23505)`),
		"mysql":    errors.New(`Error 1062 (23000): Duplicate entry 'brave-otter'`),
		"sqlite":   errors.New(`UNIQUE constraint failed: agent_network_settings.subdomain`),
	} {
		assert.True(t, isUniqueConstraintError(err), "%s violation must be recognised", name)
	}

	assert.False(t, isUniqueConstraintError(errors.New("connection refused")),
		"unrelated errors must not be treated as retryable collisions")
}

// newAllocatorTestStore wires a real sqlite store, mirroring the pattern in
// provider_bootstrap_test.go's bootstrapFixture. The allocator tests exercise
// bootstrapSettingsIfNeeded directly against a managerImpl built in-package,
// so no permissions manager or account manager is needed.
func newAllocatorTestStore(t *testing.T) store.Store {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("sqlite store not properly supported on Windows yet")
	}
	t.Setenv("NETBIRD_STORE_ENGINE", string(nbtypes.SqliteStoreEngine))

	st, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	require.NoError(t, err, "test store setup must succeed")
	t.Cleanup(cleanUp)
	return st
}

// TestBootstrapSettings_StampsZoneAndTupleLabel — new rows must carry the
// configured zone and a tuple label, which together give the tenant a
// placement-independent address.
func TestBootstrapSettings_StampsZoneAndTupleLabel(t *testing.T) {
	ctx := context.Background()
	st := newAllocatorTestStore(t)

	m := &managerImpl{
		store:    st,
		zone:     "gateway.example",
		labelRng: rand.New(rand.NewSource(1)),
	}

	settings, err := m.bootstrapSettingsIfNeeded(ctx, "account1", "cluster1.example.com")
	require.NoError(t, err, "bootstrap must succeed")
	require.NotNil(t, settings)

	assert.Equal(t, "gateway.example", settings.Zone, "new row must carry the configured zone")
	assert.Equal(t, "cluster1.example.com", settings.Cluster)
	assert.Contains(t, settings.Subdomain, "-", "subdomain must be an adjective-noun tuple label")
	assert.Equal(t, "account1", settings.AccountID)
	assert.Equal(t, settings.Subdomain+".gateway.example", settings.Endpoint(),
		"endpoint must be placement-independent, hanging off the zone rather than the cluster")

	persisted, err := st.GetAgentNetworkSettings(ctx, store.LockingStrengthNone, "account1")
	require.NoError(t, err)
	assert.Equal(t, settings.Subdomain, persisted.Subdomain, "returned settings must match the persisted row")
	assert.Equal(t, "gateway.example", persisted.Zone)
}

// TestBootstrapSettings_RetriesOnCollision forces a duplicate by pre-inserting
// a row whose subdomain matches the next label the seeded rng will draw, then
// asserts allocation still succeeds with a different label and that no error
// escapes.
func TestBootstrapSettings_RetriesOnCollision(t *testing.T) {
	ctx := context.Background()
	st := newAllocatorTestStore(t)

	const seed = 7

	// Precompute the label a freshly seeded rng will draw first, without
	// disturbing the rng the manager will actually use.
	predictor := rand.New(rand.NewSource(seed))
	firstDraw := labelgen.PickTuple(predictor)
	require.NotEmpty(t, firstDraw, "test precondition: label pools must be non-empty")

	// Pre-insert a colliding row on a different account so the allocator's
	// first attempt hits the unique index and must retry.
	require.NoError(t, st.CreateAgentNetworkSettings(ctx, &types.Settings{
		AccountID: "other-account",
		Cluster:   "cluster1.example.com",
		Subdomain: firstDraw,
	}), "seeding the colliding row must succeed")

	m := &managerImpl{
		store:    st,
		labelRng: rand.New(rand.NewSource(seed)),
	}

	settings, err := m.bootstrapSettingsIfNeeded(ctx, "account1", "cluster1.example.com")
	require.NoError(t, err, "allocation must succeed after retrying past the collision")
	require.NotNil(t, settings)
	assert.NotEqual(t, firstDraw, settings.Subdomain,
		"the retried allocation must not reuse the already-taken label")
}

// TestBootstrapSettings_IsIdempotent — calling twice for one account returns
// the existing row unchanged (the early-return path), and does NOT
// re-allocate.
func TestBootstrapSettings_IsIdempotent(t *testing.T) {
	ctx := context.Background()
	st := newAllocatorTestStore(t)

	m := &managerImpl{
		store:    st,
		labelRng: rand.New(rand.NewSource(3)),
	}

	first, err := m.bootstrapSettingsIfNeeded(ctx, "account1", "cluster1.example.com")
	require.NoError(t, err)
	require.NotNil(t, first)

	second, err := m.bootstrapSettingsIfNeeded(ctx, "account1", "cluster2.example.com")
	require.NoError(t, err, "second call must not error")
	require.NotNil(t, second)

	assert.Equal(t, first.Subdomain, second.Subdomain, "second call must return the existing subdomain unchanged")
	assert.Equal(t, first.Cluster, second.Cluster, "second call must not repin the cluster to the new hint")

	all, err := st.GetAllAgentNetworkSettings(ctx, store.LockingStrengthNone)
	require.NoError(t, err)
	var forAccount int
	for _, s := range all {
		if s.AccountID == "account1" {
			forAccount++
		}
	}
	assert.Equal(t, 1, forAccount, "exactly one row must exist for the account; no re-allocation")
}

// TestBootstrapSettings_FailsAfterExhaustingAttempts — the retry loop's
// failure mode. maxSubdomainAllocationAttempts consecutive collisions must
// surface an error rather than inserting a duplicate, silently succeeding, or
// looping forever.
//
// Seed 11 was checked to produce maxSubdomainAllocationAttempts distinct
// labels from labelgen.PickTuple; a seed that repeated a label would leave
// fewer than maxAttempts rows pre-inserted and the allocator would succeed on
// the repeat instead of exhausting.
func TestBootstrapSettings_FailsAfterExhaustingAttempts(t *testing.T) {
	ctx := context.Background()
	st := newAllocatorTestStore(t)

	const seed = 11
	predictor := rand.New(rand.NewSource(seed))
	seen := make(map[string]struct{}, maxSubdomainAllocationAttempts)
	for i := 0; i < maxSubdomainAllocationAttempts; i++ {
		label := labelgen.PickTuple(predictor)
		_, dup := seen[label]
		require.False(t, dup, "test precondition: seed %d must draw %d distinct labels, got a repeat %q at draw %d", seed, maxSubdomainAllocationAttempts, label, i)
		seen[label] = struct{}{}

		require.NoError(t, st.CreateAgentNetworkSettings(ctx, &types.Settings{
			AccountID: fmt.Sprintf("squatter-%d", i),
			Cluster:   "cluster1.example.com",
			Subdomain: label,
		}), "seeding colliding row %d must succeed", i)
	}

	m := &managerImpl{
		store:    st,
		labelRng: rand.New(rand.NewSource(seed)),
	}

	settings, err := m.bootstrapSettingsIfNeeded(ctx, "account1", "cluster1.example.com")
	require.Error(t, err, "exhausting every attempt to a collision must not silently succeed")
	assert.Nil(t, settings, "no settings row may be returned on failure")
	assert.Contains(t, err.Error(), "attempts exhausted")

	_, err = st.GetAgentNetworkSettings(ctx, store.LockingStrengthNone, "account1")
	assert.Error(t, err, "no settings row must be persisted for the account when allocation fails")
}

// TestBootstrapSettings_ConcurrentBootstrapReturnsWinnersRow covers the
// same-account race: Settings' primary key is AccountID, and the
// existence pre-check in bootstrapSettingsIfNeeded runs outside the
// transaction, so two concurrent first-provider creates for the same
// account can both observe NotFound and both proceed to allocate. The
// loser's INSERT then fails on the primary key rather than the subdomain
// unique index — a string isUniqueConstraintError still recognises — and
// must not be treated as a label collision to retry past; it must
// re-read and return the winner's row.
//
// This is scripted against a gomock store rather than driven by real
// goroutines against the sqlite test store: NewTestStoreFromSQL caps the
// pool at a single open connection (see its startup log,
// "max open db connections to 1"), which serialises statement execution
// enough that reliably forcing the exact interleaving this test needs —
// both pre-checks observing NotFound before either INSERT lands — would
// depend on goroutine scheduling rather than the store, making a
// real-goroutine version flaky rather than deterministic. Scripting the
// exact sequence (pre-check miss, PK-shaped insert failure, re-read hit)
// through a MockStore exercises the same re-read branch precisely and
// deterministically.
func TestBootstrapSettings_ConcurrentBootstrapReturnsWinnersRow(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	mockStore := store.NewMockStore(ctrl)

	winner := &types.Settings{
		AccountID: "account1",
		Cluster:   "cluster1.example.com",
		Subdomain: "brave-otter",
	}

	gomock.InOrder(
		// The pre-check: no row yet, so this bootstrap proceeds to allocate.
		mockStore.EXPECT().
			GetAgentNetworkSettings(gomock.Any(), store.LockingStrengthNone, "account1").
			Return(nil, status.Errorf(status.NotFound, "agent network settings not found")),
		// The insert loses the race. The message shape is the sqlite wording
		// for a primary-key violation on account_id (not the subdomain
		// index), per the review finding this test locks down.
		mockStore.EXPECT().
			ExecuteInTransaction(gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, f func(store.Store) error) error {
				return f(mockStore)
			}),
		// The re-read after the PK conflict finds the concurrent winner's row.
		mockStore.EXPECT().
			GetAgentNetworkSettings(gomock.Any(), store.LockingStrengthNone, "account1").
			Return(winner, nil),
	)
	mockStore.EXPECT().
		CreateAgentNetworkSettings(gomock.Any(), gomock.Any()).
		Return(errors.New("UNIQUE constraint failed: agent_network_settings.account_id"))

	m := &managerImpl{
		store:    mockStore,
		labelRng: rand.New(rand.NewSource(9)),
	}

	settings, err := m.bootstrapSettingsIfNeeded(ctx, "account1", "cluster1.example.com")
	require.NoError(t, err, "losing the same-account race must not surface as an error")
	require.NotNil(t, settings)
	assert.Same(t, winner, settings, "the loser must return the concurrent winner's row, not retry past it")
}
