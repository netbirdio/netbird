package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	agentNetworkTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
)

// TestAgentNetworkUsage_RealStore_RoundTrip drives CreateAgentNetworkUsage and
// CreateAgentNetworkAccessLog through a real sqlite store to prove the schema
// migrates and the inserts succeed for both a populated (allowed) entry and a
// stripped (denied) entry.
func TestAgentNetworkUsage_RealStore_RoundTrip(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	defer cleanup()

	const accountID = "acc-anet-usage-1"
	now := time.Now().UTC()

	// Populated (allowed) usage row with two authorising groups.
	usage := &agentNetworkTypes.AgentNetworkUsage{
		ID:                 "log-allowed-1",
		AccountID:          accountID,
		Timestamp:          now,
		UserID:             "user-alice",
		ResolvedProviderID: "prov-openai-1",
		Provider:           "openai",
		Model:              "gpt-4o",
		SessionID:          "sess-round-trip-1",
		InputTokens:        1200,
		OutputTokens:       640,
		TotalTokens:        1840,
		CostUSD:            0.0231,
	}
	usageGroups := []agentNetworkTypes.AgentNetworkUsageGroup{
		{UsageID: usage.ID, GroupID: "grp-eng", AccountID: accountID},
		{UsageID: usage.ID, GroupID: "grp-oncall", AccountID: accountID},
	}
	require.NoError(t, s.CreateAgentNetworkUsage(ctx, usage, usageGroups), "populated usage insert must succeed")

	// Stripped (denied / 403) usage row: no provider/model/tokens, no groups.
	denied := &agentNetworkTypes.AgentNetworkUsage{
		ID:        "log-denied-1",
		AccountID: accountID,
		Timestamp: now,
		UserID:    "user-bob",
	}
	require.NoError(t, s.CreateAgentNetworkUsage(ctx, denied, nil), "stripped usage insert must succeed")

	// Idempotency: re-inserting the same id must not error.
	require.NoError(t, s.CreateAgentNetworkUsage(ctx, usage, usageGroups), "duplicate usage insert must be idempotent")

	// Access-log row + group children.
	entry := &agentNetworkTypes.AgentNetworkAccessLog{
		ID:           "log-allowed-1",
		AccountID:    accountID,
		ServiceID:    "agent-net-svc-1",
		Timestamp:    now,
		UserID:       "user-alice",
		StatusCode:   200,
		Provider:     "openai",
		Model:        "gpt-4o",
		SessionID:    "sess-round-trip-1",
		InputTokens:  1200,
		OutputTokens: 640,
		TotalTokens:  1840,
		CostUSD:      0.0231,
	}
	entryGroups := []agentNetworkTypes.AgentNetworkAccessLogGroup{
		{LogID: entry.ID, GroupID: "grp-eng", AccountID: accountID},
		{LogID: entry.ID, GroupID: "grp-oncall", AccountID: accountID},
	}
	require.NoError(t, s.CreateAgentNetworkAccessLog(ctx, entry, entryGroups), "access-log insert must succeed")

	// Read back through the filtered list + verify group hydration.
	logs, total, err := s.GetAgentNetworkAccessLogs(ctx, LockingStrengthNone, accountID, agentNetworkTypes.AgentNetworkAccessLogFilter{Page: 1, PageSize: 50})
	require.NoError(t, err, "list must succeed")
	assert.Equal(t, int64(1), total, "one access-log row expected")
	require.Len(t, logs, 1)
	assert.ElementsMatch(t, []string{"grp-eng", "grp-oncall"}, logs[0].GroupIDs, "group ids must hydrate")
	assert.Equal(t, "sess-round-trip-1", logs[0].SessionID, "session id must persist and read back on the access-log row")

	// Session filter narrows the access-log listing to one conversation.
	sessionID := "sess-round-trip-1"
	sessLogs, sessTotal, err := s.GetAgentNetworkAccessLogs(ctx, LockingStrengthNone, accountID,
		agentNetworkTypes.AgentNetworkAccessLogFilter{Page: 1, PageSize: 50, SessionID: &sessionID})
	require.NoError(t, err)
	assert.Equal(t, int64(1), sessTotal, "session filter must match the one row with that session id")
	require.Len(t, sessLogs, 1)
	assert.Equal(t, entry.ID, sessLogs[0].ID, "session filter must return the matching log row")

	bogus := "no-such-session"
	_, emptyTotal, err := s.GetAgentNetworkAccessLogs(ctx, LockingStrengthNone, accountID,
		agentNetworkTypes.AgentNetworkAccessLogFilter{Page: 1, PageSize: 50, SessionID: &bogus})
	require.NoError(t, err)
	assert.Equal(t, int64(0), emptyTotal, "unknown session id must match nothing")

	// Session filter also narrows the always-on usage rows.
	sessUsage, err := s.GetAgentNetworkUsageRows(ctx, LockingStrengthNone, accountID,
		agentNetworkTypes.AgentNetworkAccessLogFilter{SessionID: &sessionID})
	require.NoError(t, err)
	require.Len(t, sessUsage, 1, "session filter must narrow usage rows to the matching session")
	assert.Equal(t, "sess-round-trip-1", sessUsage[0].SessionID, "usage row must carry the session id")
}

// TestAgentNetworkUsageOverview_DailyAggregation drives GetAgentNetworkUsageRows
// + AggregateUsageByGranularity end-to-end against a real sqlite store, with
// two rows on the same day and one on another, plus a model filter.
func TestAgentNetworkUsageOverview_DailyAggregation(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	defer cleanup()

	const accountID = "acc-anet-overview-1"
	day1 := time.Date(2026, 5, 5, 10, 0, 0, 0, time.UTC)
	day1b := time.Date(2026, 5, 5, 22, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 5, 6, 9, 0, 0, 0, time.UTC)

	mk := func(id string, ts time.Time, model string, in, out int64, cost float64) *agentNetworkTypes.AgentNetworkUsage {
		return &agentNetworkTypes.AgentNetworkUsage{
			ID: id, AccountID: accountID, Timestamp: ts, Model: model,
			InputTokens: in, OutputTokens: out, TotalTokens: in + out, CostUSD: cost,
		}
	}
	require.NoError(t, s.CreateAgentNetworkUsage(ctx, mk("u1", day1, "gpt-4o", 100, 50, 0.10), nil))
	require.NoError(t, s.CreateAgentNetworkUsage(ctx, mk("u2", day1b, "gpt-4o", 200, 80, 0.20), nil))
	require.NoError(t, s.CreateAgentNetworkUsage(ctx, mk("u3", day2, "claude-3", 10, 5, 0.01), nil))

	rows, err := s.GetAgentNetworkUsageRows(ctx, LockingStrengthNone, accountID, agentNetworkTypes.AgentNetworkAccessLogFilter{})
	require.NoError(t, err)
	require.Len(t, rows, 3, "all three usage rows expected")

	buckets := agentNetworkTypes.AggregateUsageByGranularity(rows, agentNetworkTypes.UsageGranularityDay)
	require.Len(t, buckets, 2, "two distinct days expected")
	assert.Equal(t, "2026-05-05", buckets[0].PeriodStart, "oldest-first ordering")
	assert.Equal(t, int64(300), buckets[0].InputTokens, "same-day input tokens summed")
	assert.Equal(t, int64(130), buckets[0].OutputTokens)
	assert.InDelta(t, 0.30, buckets[0].CostUSD, 1e-9, "same-day cost summed")
	assert.Equal(t, "2026-05-06", buckets[1].PeriodStart)
	assert.Equal(t, int64(15), buckets[1].TotalTokens)

	// Model filter narrows to a single day.
	model := "claude-3"
	filtered, err := s.GetAgentNetworkUsageRows(ctx, LockingStrengthNone, accountID, agentNetworkTypes.AgentNetworkAccessLogFilter{Models: []string{model}})
	require.NoError(t, err)
	require.Len(t, filtered, 1, "model filter must narrow rows")
	assert.Equal(t, "u3", filtered[0].ID)
}

// TestAgentNetworkAccessLogSessions_RealStore drives GetAgentNetworkAccessLogSessions
// against a real sqlite store: session grouping + aggregation, recency ordering,
// singleton groups for session-less requests, session pagination, the model
// filter narrowing sessions, and aggregate sorting.
func TestAgentNetworkAccessLogSessions_RealStore(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	defer cleanup()

	const accountID = "acc-anet-sessions-1"
	base := time.Date(2026, 5, 5, 10, 0, 0, 0, time.UTC)
	at := func(h int) time.Time { return base.Add(time.Duration(h) * time.Hour) }

	mk := func(id, session, user, provider, model, decision string, ts time.Time, cost float64) *agentNetworkTypes.AgentNetworkAccessLog {
		return &agentNetworkTypes.AgentNetworkAccessLog{
			ID: id, AccountID: accountID, ServiceID: "svc", Timestamp: ts,
			UserID: user, StatusCode: 200, Provider: provider, Model: model,
			SessionID: session, Decision: decision,
			InputTokens: 100, OutputTokens: 50, TotalTokens: 150, CostUSD: cost,
		}
	}

	// Two-request session s1 (alice), a one-request denied session s2 (bob), and
	// two session-less requests (empty session id) that must each form their own
	// singleton group.
	require.NoError(t, s.CreateAgentNetworkAccessLog(ctx, mk("s1-a", "s1", "alice", "openai", "gpt-4o", "allow", at(1), 0.10),
		[]agentNetworkTypes.AgentNetworkAccessLogGroup{{LogID: "s1-a", GroupID: "grp-eng", AccountID: accountID}}))
	require.NoError(t, s.CreateAgentNetworkAccessLog(ctx, mk("s1-b", "s1", "alice", "openai", "gpt-4o", "allow", at(2), 0.20),
		[]agentNetworkTypes.AgentNetworkAccessLogGroup{{LogID: "s1-b", GroupID: "grp-oncall", AccountID: accountID}}))
	require.NoError(t, s.CreateAgentNetworkAccessLog(ctx, mk("s2-a", "s2", "bob", "anthropic", "claude-3", "deny", at(3), 0.05), nil))
	require.NoError(t, s.CreateAgentNetworkAccessLog(ctx, mk("se-old", "", "carol", "openai", "o1", "allow", at(0), 0.01), nil))
	require.NoError(t, s.CreateAgentNetworkAccessLog(ctx, mk("se-new", "", "dave", "mistral", "mistral-large", "allow", at(4), 0.02), nil))

	// Default sort: last activity (MAX timestamp) descending.
	sessions, total, err := s.GetAgentNetworkAccessLogSessions(ctx, LockingStrengthNone, accountID,
		agentNetworkTypes.AgentNetworkAccessLogFilter{Page: 1, PageSize: 50})
	require.NoError(t, err)
	assert.Equal(t, int64(4), total, "four sessions: s1, s2, and two singletons")
	require.Len(t, sessions, 4)

	// se-new(t4) > s2(t3) > s1(t2) > se-old(t0)
	assert.Equal(t, "", sessions[0].SessionID, "newest is a session-less singleton")
	assert.Equal(t, "se-new", sessions[0].Entries[0].ID)
	assert.Equal(t, "s2", sessions[1].SessionID)
	assert.Equal(t, "s1", sessions[2].SessionID)
	assert.Equal(t, "se-old", sessions[3].Entries[0].ID)

	// s1 aggregation.
	s1 := sessions[2]
	assert.Equal(t, 2, s1.RequestCount, "s1 has two requests")
	assert.Equal(t, int64(300), s1.TotalTokens, "tokens summed across the session")
	assert.InDelta(t, 0.30, s1.CostUSD, 1e-9, "cost summed across the session")
	assert.Equal(t, "alice", s1.UserID)
	assert.Equal(t, "allow", s1.Decision)
	assert.Equal(t, at(1), s1.StartedAt, "started = earliest entry")
	assert.Equal(t, at(2), s1.EndedAt, "ended = latest entry")
	assert.ElementsMatch(t, []string{"openai"}, s1.Providers)
	assert.ElementsMatch(t, []string{"gpt-4o"}, s1.Models)
	assert.ElementsMatch(t, []string{"grp-eng", "grp-oncall"}, s1.GroupIDs, "union of the entries' authorising groups")

	// Denied session rolls up to deny.
	assert.Equal(t, "deny", sessions[1].Decision, "any denied request makes the session deny")

	// Pagination over sessions: 2 per page.
	page1, total, err := s.GetAgentNetworkAccessLogSessions(ctx, LockingStrengthNone, accountID,
		agentNetworkTypes.AgentNetworkAccessLogFilter{Page: 1, PageSize: 2})
	require.NoError(t, err)
	assert.Equal(t, int64(4), total, "total still counts all sessions")
	require.Len(t, page1, 2)
	assert.Equal(t, "se-new", page1[0].Entries[0].ID)
	assert.Equal(t, "s2", page1[1].SessionID)

	page2, _, err := s.GetAgentNetworkAccessLogSessions(ctx, LockingStrengthNone, accountID,
		agentNetworkTypes.AgentNetworkAccessLogFilter{Page: 2, PageSize: 2})
	require.NoError(t, err)
	require.Len(t, page2, 2)
	assert.Equal(t, "s1", page2[0].SessionID)
	assert.Equal(t, "se-old", page2[1].Entries[0].ID)

	// Model filter narrows to the session(s) with matching entries.
	model := "claude-3"
	filtered, fTotal, err := s.GetAgentNetworkAccessLogSessions(ctx, LockingStrengthNone, accountID,
		agentNetworkTypes.AgentNetworkAccessLogFilter{Page: 1, PageSize: 50, Models: []string{model}})
	require.NoError(t, err)
	assert.Equal(t, int64(1), fTotal, "only s2 has a claude-3 request")
	require.Len(t, filtered, 1)
	assert.Equal(t, "s2", filtered[0].SessionID)

	// Sort by total session cost, descending: s1 (0.30) leads despite not being
	// the most recent.
	byCost, _, err := s.GetAgentNetworkAccessLogSessions(ctx, LockingStrengthNone, accountID,
		agentNetworkTypes.AgentNetworkAccessLogFilter{Page: 1, PageSize: 50, SortBy: "cost_usd", SortOrder: "desc"})
	require.NoError(t, err)
	require.Len(t, byCost, 4)
	assert.Equal(t, "s1", byCost[0].SessionID, "highest-cost session sorts first")
}

// TestDeleteOldAgentNetworkAccessLogs verifies the retention sweep removes only
// access-log rows (and their group children) older than the cutoff, leaving
// recent rows — and never touching usage records.
func TestDeleteOldAgentNetworkAccessLogs(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	defer cleanup()

	const accountID = "acc-anet-retention-1"
	old := time.Now().UTC().AddDate(0, 0, -40)
	recent := time.Now().UTC().AddDate(0, 0, -1)

	mkLog := func(id string, ts time.Time) (*agentNetworkTypes.AgentNetworkAccessLog, []agentNetworkTypes.AgentNetworkAccessLogGroup) {
		return &agentNetworkTypes.AgentNetworkAccessLog{
				ID: id, AccountID: accountID, ServiceID: "svc", Timestamp: ts, StatusCode: 200, Model: "gpt-4o",
			}, []agentNetworkTypes.AgentNetworkAccessLogGroup{
				{LogID: id, GroupID: "grp-eng", AccountID: accountID},
			}
	}
	oldEntry, oldGroups := mkLog("old-1", old)
	recentEntry, recentGroups := mkLog("recent-1", recent)
	require.NoError(t, s.CreateAgentNetworkAccessLog(ctx, oldEntry, oldGroups))
	require.NoError(t, s.CreateAgentNetworkAccessLog(ctx, recentEntry, recentGroups))
	// A usage row for the old request must survive the access-log sweep.
	require.NoError(t, s.CreateAgentNetworkUsage(ctx, &agentNetworkTypes.AgentNetworkUsage{
		ID: "old-1", AccountID: accountID, Timestamp: old, Model: "gpt-4o", InputTokens: 10, TotalTokens: 10,
	}, nil))

	cutoff := time.Now().UTC().AddDate(0, 0, -30)
	deleted, err := s.DeleteOldAgentNetworkAccessLogs(ctx, accountID, cutoff)
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted, "only the 40-day-old log is deleted")

	logs, total, err := s.GetAgentNetworkAccessLogs(ctx, LockingStrengthNone, accountID, agentNetworkTypes.AgentNetworkAccessLogFilter{Page: 1, PageSize: 50})
	require.NoError(t, err)
	assert.Equal(t, int64(1), total, "the recent log remains")
	require.Len(t, logs, 1)
	assert.Equal(t, "recent-1", logs[0].ID)

	// Usage is untouched by the access-log retention sweep.
	usage, err := s.GetAgentNetworkUsageRows(ctx, LockingStrengthNone, accountID, agentNetworkTypes.AgentNetworkAccessLogFilter{})
	require.NoError(t, err)
	require.Len(t, usage, 1, "usage record for the deleted log must survive")
}
