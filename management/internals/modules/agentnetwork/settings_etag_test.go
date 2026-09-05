package agentnetwork

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/store"
	httputil "github.com/netbirdio/netbird/shared/management/http/util"
	"github.com/netbirdio/netbird/shared/management/status"
)

// ifMatch builds the precondition a client sending this validator would
// produce, by going through the same header parse the handler uses rather than
// reaching past it.
func ifMatch(t *testing.T, etag string) *httputil.Precondition {
	t.Helper()

	r := httptest.NewRequest(http.MethodPut, "/", nil)
	r.Header.Set("If-Match", strconv.Quote(etag))
	return httputil.IfMatch(r)
}

// updateFor renders a complete update for the given row, echoing the identity
// fields the endpoint requires and setting retention to tell writers apart.
func updateFor(settings *types.Settings, retention int) *types.Settings {
	return &types.Settings{
		AccountID:              settings.AccountID,
		Domain:                 settings.Domain,
		ProxyAddress:           settings.ProxyAddress,
		EnableLogCollection:    true,
		EnablePromptCollection: true,
		RedactPii:              true,
		AccessLogRetentionDays: retention,
	}
}

// TestUpdateSettingsPreconditionSerializesConcurrentWriters is the test the
// design rests on. Two writers start from the same validator and race; exactly
// one may win.
//
// An implementation that compares the validator before opening the write
// transaction passes every sequential test in this suite and fails here: both
// writers read the same row, both find their precondition satisfied, and both
// then write — which is the lost update the feature exists to prevent, merely
// narrowed to a smaller window. Holding the row under LockingStrengthUpdate
// and comparing inside the write's own transaction is what makes it a genuine
// compare-and-set.
//
// The test store is sqlite, which serializes writers of its own accord, so
// what this pins directly is the outcome — exactly one success — rather than
// the mechanism. It still has teeth against the check-before-transaction
// shape, whose two reads interleave freely before either write. Running it
// against postgres (NB_STORE_ENGINE_POSTGRES_DSN) exercises real concurrent
// transactions.
func TestUpdateSettingsPreconditionSerializesConcurrentWriters(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)

	const accountID, userID = "account1", "user1"
	f.expectPermission(accountID, userID, modules.AgentNetworkSettings, operations.Create, true)
	f.expectPermission(accountID, userID, modules.AgentNetworkSettings, operations.Update, true)
	f.expectPermission(accountID, userID, modules.AgentNetworkSettings, operations.Update, true)

	created, err := f.createSettings(ctx, accountID, userID, "cluster1.example.com", "")
	require.NoError(t, err, "bootstrap must succeed")

	// Both writers plan against this one read, as a client that read, computed
	// a diff and is about to write the whole object back would.
	shared := created.ETag()

	// noWrite is a retention value neither writer sends and the API would
	// never store, so an assertion that lands on it is a test bug rather than
	// a silently satisfied comparison. Zero would not do: the API documents 0
	// as "keep indefinitely", so it is a value the row could legitimately hold.
	const noWrite = -1

	var (
		wg       sync.WaitGroup
		start    = make(chan struct{})
		errs     = make([]error, 2)
		wrote    = []int{7, 21}
		returned = []int{noWrite, noWrite}
	)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			updated, err := f.manager.UpdateSettings(ctx, userID, updateFor(created, wrote[i]), ifMatch(t, shared))
			errs[i] = err
			if err == nil {
				returned[i] = updated.AccessLogRetentionDays
			}
		}()
	}
	close(start)
	wg.Wait()

	succeeded, winner := 0, noWrite
	for i, err := range errs {
		if err == nil {
			succeeded++
			winner = wrote[i]
			assert.Equal(t, wrote[i], returned[i], "the winner's response must carry what it sent")
			continue
		}
		assert.Truef(t, isPreconditionFailed(err),
			"the losing writer must be refused for staleness, got: %v (writer %d)", err, i)
	}
	require.Equal(t, 1, succeeded, "exactly one writer may win: %v", errs)

	// The row must carry the winner's value and nothing blended.
	stored, err := f.store.GetAgentNetworkSettings(ctx, store.LockingStrengthNone, accountID)
	require.NoError(t, err, "the row must survive the race")
	assert.Equal(t, winner, stored.AccessLogRetentionDays,
		"the stored row must be exactly what the winning writer sent")
	assert.NotEqual(t, shared, stored.ETag(), "the surviving row must derive a new validator")
}

// TestUpdateSettingsUnconditionalIgnoresStaleness pins the back-compatibility
// half: without a precondition the manager keeps last-write-wins, which is
// what the dashboard relies on and what any client that predates conditional
// requests does.
func TestUpdateSettingsUnconditionalIgnoresStaleness(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)

	const accountID, userID = "account1", "user1"
	f.expectPermission(accountID, userID, modules.AgentNetworkSettings, operations.Create, true)
	f.expectPermission(accountID, userID, modules.AgentNetworkSettings, operations.Update, true)
	f.expectPermission(accountID, userID, modules.AgentNetworkSettings, operations.Update, true)

	created, err := f.createSettings(ctx, accountID, userID, "cluster1.example.com", "")
	require.NoError(t, err, "bootstrap must succeed")

	_, err = f.manager.UpdateSettings(ctx, userID, updateFor(created, 21), nil)
	require.NoError(t, err, "the first unconditional update must succeed")

	// The second writer is working from a read that is now stale, and with no
	// precondition it overwrites regardless.
	updated, err := f.manager.UpdateSettings(ctx, userID, updateFor(created, 7), nil)
	require.NoError(t, err, "an unconditional update must not be refused for staleness")
	assert.Equal(t, 7, updated.AccessLogRetentionDays, "last write wins without a precondition")
}

// TestDeleteSettingsPreconditionRefusesStale pins the conditional delete at
// the manager level: a stale validator refuses, and the row is still there
// afterwards. Deletion is the destructive operation and its two other guards
// are about state rather than staleness, so this is the only thing standing
// between a client working from an old read and a released endpoint.
func TestDeleteSettingsPreconditionRefusesStale(t *testing.T) {
	ctx := context.Background()
	f := newBootstrapFixture(t)

	const accountID, userID = "account1", "user1"
	f.expectPermission(accountID, userID, modules.AgentNetworkSettings, operations.Create, true)
	f.expectPermission(accountID, userID, modules.AgentNetworkSettings, operations.Update, true)
	f.expectPermission(accountID, userID, modules.AgentNetworkSettings, operations.Delete, true)
	f.expectPermission(accountID, userID, modules.AgentNetworkSettings, operations.Delete, true)

	created, err := f.createSettings(ctx, accountID, userID, "cluster1.example.com", "")
	require.NoError(t, err, "bootstrap must succeed")
	stale := created.ETag()

	updated, err := f.manager.UpdateSettings(ctx, userID, updateFor(created, 21), nil)
	require.NoError(t, err, "the intervening update must succeed")

	err = f.manager.DeleteSettings(ctx, accountID, userID, ifMatch(t, stale))
	require.Error(t, err, "a stale precondition must refuse the delete")
	assert.True(t, isPreconditionFailed(err), "the refusal must be a precondition failure, got: %v", err)

	stored, err := f.store.GetAgentNetworkSettings(ctx, store.LockingStrengthNone, accountID)
	require.NoError(t, err, "the refused delete must leave the row in place")
	assert.Equal(t, created.Domain, stored.Domain, "the endpoint must not have been released")

	// The validator the intervening update returned is the current one, and
	// deleting with it goes through.
	require.NoError(t, f.manager.DeleteSettings(ctx, accountID, userID, ifMatch(t, updated.ETag())),
		"a matching precondition must be honoured")
	_, err = f.store.GetAgentNetworkSettings(ctx, store.LockingStrengthNone, accountID)
	assert.Error(t, err, "the row must be gone")
}

// isPreconditionFailed reports whether err is the 412-mapped status error.
func isPreconditionFailed(err error) bool {
	var sErr *status.Error
	return errors.As(err, &sErr) && sErr.Type() == status.PreconditionFailed
}
