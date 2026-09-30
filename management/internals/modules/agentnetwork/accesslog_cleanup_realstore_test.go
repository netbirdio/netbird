package agentnetwork

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/server/store"
)

// TestCleanupAccessLogs_RealStore_AccountWithoutSettings covers an account whose settings
// row is gone, as after account deletion. The sweep is driven by settings rows, so without
// a fallback that account's access logs would never expire. They get the default
// retention instead, while an account that keeps its logs indefinitely is left alone.
func TestCleanupAccessLogs_RealStore_AccountWithoutSettings(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	defer cleanup()

	const (
		deletedAccountID = "acc-deleted"
		keepAccountID    = "acc-keep-forever"
	)
	old := time.Now().UTC().AddDate(0, 0, -(types.DefaultAccessLogRetentionDays + 10))
	recent := time.Now().UTC().AddDate(0, 0, -1)

	keepSettings := types.DefaultSettings(keepAccountID)
	keepSettings.Domain = "keep.gw.example.com"
	keepSettings.AccessLogRetentionDays = 0
	require.NoError(t, s.SaveAgentNetworkSettings(ctx, keepSettings))

	mkLog := func(id, accountID string, ts time.Time) {
		t.Helper()
		entry := &types.AgentNetworkAccessLog{
			ID: id, AccountID: accountID, ServiceID: "svc", Timestamp: ts, StatusCode: 200, Model: "gpt-4o",
		}
		groups := []types.AgentNetworkAccessLogGroup{{LogID: id, GroupID: "grp-eng", AccountID: accountID}}
		require.NoError(t, s.CreateAgentNetworkAccessLog(ctx, entry, groups))
	}
	mkLog("deleted-old", deletedAccountID, old)
	mkLog("deleted-recent", deletedAccountID, recent)
	mkLog("keep-old", keepAccountID, old)

	m := &managerImpl{store: s}
	m.cleanupAccessLogsOnce(ctx)

	logIDs := func(accountID string) []string {
		t.Helper()
		logs, _, err := s.GetAgentNetworkAccessLogs(ctx, store.LockingStrengthNone, accountID,
			types.AgentNetworkAccessLogFilter{Page: 1, PageSize: 50})
		require.NoError(t, err)
		ids := make([]string, 0, len(logs))
		for _, l := range logs {
			ids = append(ids, l.ID)
		}
		return ids
	}
	assert.Equal(t, []string{"deleted-recent"}, logIDs(deletedAccountID),
		"an account without settings should have logs past the default retention swept")
	assert.Equal(t, []string{"keep-old"}, logIDs(keepAccountID),
		"an account with retention disabled should keep its old logs")
}
