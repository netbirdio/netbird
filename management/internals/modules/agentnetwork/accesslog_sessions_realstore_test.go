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

// baseTime is a fixed reference so session timestamps (and therefore the
// default MAX(timestamp) DESC ordering) are deterministic across runs.
var baseTime = time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)

// accessLogRow builds an agent-network access-log row for the shared test
// account. Functional options tweak the LLM dimensions a given test cares
// about; everything else gets a sane, allow/200 default.
func accessLogRow(id, sessionID string, ts time.Time, opts ...func(*types.AgentNetworkAccessLog)) *types.AgentNetworkAccessLog {
	e := &types.AgentNetworkAccessLog{
		ID:                 id,
		AccountID:          testAccountID,
		ServiceID:          "svc-1",
		Timestamp:          ts,
		UserID:             "user-1",
		SessionID:          sessionID,
		Method:             "POST",
		Host:               testEndpoint,
		Path:               "/v1/chat/completions",
		StatusCode:         200,
		Decision:           "allow",
		Provider:           "openai",
		Model:              "gpt-5.4",
		ResolvedProviderID: "prov-1",
		InputTokens:        100,
		OutputTokens:       50,
		TotalTokens:        150,
		CostUSD:            0.01,
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

func withUser(u string) func(*types.AgentNetworkAccessLog) {
	return func(e *types.AgentNetworkAccessLog) { e.UserID = u }
}

func withModel(m string) func(*types.AgentNetworkAccessLog) {
	return func(e *types.AgentNetworkAccessLog) { e.Model = m }
}

func withProvider(vendor, resolvedID string) func(*types.AgentNetworkAccessLog) {
	return func(e *types.AgentNetworkAccessLog) {
		e.Provider = vendor
		e.ResolvedProviderID = resolvedID
	}
}

func withDeny(reason string) func(*types.AgentNetworkAccessLog) {
	return func(e *types.AgentNetworkAccessLog) {
		e.Decision = "deny"
		e.DenyReason = reason
		e.StatusCode = 403
	}
}

func withTokens(in, out, total int64, cost float64) func(*types.AgentNetworkAccessLog) {
	return func(e *types.AgentNetworkAccessLog) {
		e.InputTokens = in
		e.OutputTokens = out
		e.TotalTokens = total
		e.CostUSD = cost
	}
}

func withGroups(gids ...string) func(*types.AgentNetworkAccessLog) {
	return func(e *types.AgentNetworkAccessLog) { e.GroupIDs = gids }
}

// seedAccessLogs writes rows (and their authorising-group child rows) directly
// into the store, bypassing ingest so a test can control every dimension.
func seedAccessLogs(t *testing.T, s store.Store, rows ...*types.AgentNetworkAccessLog) {
	t.Helper()
	ctx := context.Background()
	for _, r := range rows {
		var groups []types.AgentNetworkAccessLogGroup
		for _, g := range r.GroupIDs {
			groups = append(groups, types.AgentNetworkAccessLogGroup{
				LogID:     r.ID,
				GroupID:   g,
				AccountID: r.AccountID,
			})
		}
		require.NoError(t, s.CreateAgentNetworkAccessLog(ctx, r, groups), "seed access-log row %s", r.ID)
	}
}

func newSessionsTestStore(t *testing.T) store.Store {
	t.Helper()
	s, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	t.Cleanup(cleanup)
	return s
}

// sessionIDs projects the session ids from a page of session summaries, in
// order, for concise ordering assertions.
func sessionIDs(sessions []*types.AgentNetworkAccessLogSession) []string {
	out := make([]string, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, s.SessionID)
	}
	return out
}

// TestAccessLogSessions_FoldAndAggregate verifies that multiple entries sharing
// a session id fold into one summary with summed usage, distinct
// provider/model lists, a deny rollup, and correct first/last activity bounds.
func TestAccessLogSessions_FoldAndAggregate(t *testing.T) {
	ctx := context.Background()
	s := newSessionsTestStore(t)

	// sess-a: three entries spanning 3 minutes, two providers/models, one deny.
	seedAccessLogs(t, s,
		accessLogRow("a1", "sess-a", baseTime,
			withProvider("openai", "prov-openai"), withModel("gpt-5.4"),
			withTokens(100, 50, 150, 0.01), withGroups("grp-eng")),
		accessLogRow("a2", "sess-a", baseTime.Add(1*time.Minute),
			withProvider("anthropic", "prov-anthropic"), withModel("claude-haiku-4-5"),
			withTokens(200, 80, 280, 0.02), withGroups("grp-eng", "grp-ops")),
		accessLogRow("a3", "sess-a", baseTime.Add(2*time.Minute),
			withProvider("openai", "prov-openai"), withModel("gpt-5.4"),
			withTokens(10, 5, 15, 0.001), withDeny("llm_policy.token_cap_exceeded")),
		// sess-b: a single allow entry.
		accessLogRow("b1", "sess-b", baseTime.Add(30*time.Minute),
			withTokens(1, 2, 3, 0.5)),
	)

	sessions, total, err := s.GetAgentNetworkAccessLogSessions(ctx, store.LockingStrengthNone, testAccountID, types.AgentNetworkAccessLogFilter{})
	require.NoError(t, err)
	require.Equal(t, int64(2), total, "two distinct sessions")
	require.Len(t, sessions, 2)

	// Default sort is last-activity DESC, so sess-b (12:30) precedes sess-a (12:02).
	require.Equal(t, []string{"sess-b", "sess-a"}, sessionIDs(sessions))

	a := sessions[1]
	assert.Equal(t, "sess-a", a.SessionID)
	assert.Equal(t, 3, a.RequestCount, "three requests folded")
	assert.Equal(t, int64(310), a.InputTokens, "input tokens summed")
	assert.Equal(t, int64(135), a.OutputTokens, "output tokens summed")
	assert.Equal(t, int64(445), a.TotalTokens, "total tokens summed")
	assert.InDelta(t, 0.031, a.CostUSD, 1e-9, "cost summed")
	assert.Equal(t, "deny", a.Decision, "any deny makes the session a deny")
	assert.ElementsMatch(t, []string{"openai", "anthropic"}, a.Providers, "distinct providers")
	assert.ElementsMatch(t, []string{"gpt-5.4", "claude-haiku-4-5"}, a.Models, "distinct models")
	assert.ElementsMatch(t, []string{"grp-eng", "grp-ops"}, a.GroupIDs, "union of authorising groups")
	assert.Equal(t, baseTime, a.StartedAt.UTC(), "started at is the earliest entry")
	assert.Equal(t, baseTime.Add(2*time.Minute), a.EndedAt.UTC(), "ended at is the latest entry")
	assert.Len(t, a.Entries, 3, "entries carried through")

	b := sessions[0]
	assert.Equal(t, "sess-b", b.SessionID)
	assert.Equal(t, 1, b.RequestCount)
	assert.Equal(t, "allow", b.Decision)
}

// TestAccessLogSessions_SessionlessRowsAreSingletons verifies that entries with
// no session id each form their own singleton session keyed by the row id.
func TestAccessLogSessions_SessionlessRowsAreSingletons(t *testing.T) {
	ctx := context.Background()
	s := newSessionsTestStore(t)

	seedAccessLogs(t, s,
		accessLogRow("solo-1", "", baseTime),
		accessLogRow("solo-2", "", baseTime.Add(time.Minute)),
		// A real session with two entries, to prove they don't merge with the singletons.
		accessLogRow("g1", "sess-x", baseTime.Add(2*time.Minute)),
		accessLogRow("g2", "sess-x", baseTime.Add(3*time.Minute)),
	)

	sessions, total, err := s.GetAgentNetworkAccessLogSessions(ctx, store.LockingStrengthNone, testAccountID, types.AgentNetworkAccessLogFilter{})
	require.NoError(t, err)
	require.Equal(t, int64(3), total, "two singletons + one grouped session")
	require.Len(t, sessions, 3)

	for _, sess := range sessions {
		if sess.SessionID == "sess-x" {
			assert.Equal(t, 2, sess.RequestCount, "grouped session folds both entries")
		} else {
			assert.Empty(t, sess.SessionID, "singleton carries no session id")
			assert.Equal(t, 1, sess.RequestCount, "singleton has exactly one request")
		}
	}
}

// TestAccessLogSessions_Pagination verifies that paging returns the correct
// slice of sessions in stable order, with a stable total across pages and no
// overlap between pages.
func TestAccessLogSessions_Pagination(t *testing.T) {
	ctx := context.Background()
	s := newSessionsTestStore(t)

	// Five sessions, each a single entry, with increasing timestamps so the
	// default MAX(timestamp) DESC order is sess-5, sess-4, sess-3, sess-2, sess-1.
	rows := make([]*types.AgentNetworkAccessLog, 0, 5)
	for i := 1; i <= 5; i++ {
		rows = append(rows, accessLogRow(
			"row-"+itoa(i), "sess-"+itoa(i), baseTime.Add(time.Duration(i)*time.Minute)))
	}
	seedAccessLogs(t, s, rows...)

	page := func(p int) []*types.AgentNetworkAccessLogSession {
		sessions, total, err := s.GetAgentNetworkAccessLogSessions(ctx, store.LockingStrengthNone, testAccountID,
			types.AgentNetworkAccessLogFilter{Page: p, PageSize: 2})
		require.NoError(t, err)
		require.Equal(t, int64(5), total, "total session count is stable across pages")
		return sessions
	}

	assert.Equal(t, []string{"sess-5", "sess-4"}, sessionIDs(page(1)), "page 1: two newest")
	assert.Equal(t, []string{"sess-3", "sess-2"}, sessionIDs(page(2)), "page 2: next two")
	assert.Equal(t, []string{"sess-1"}, sessionIDs(page(3)), "page 3: remaining one")
	assert.Empty(t, page(4), "page 4: past the end is empty")
}

// TestAccessLogSessions_Filtering verifies each filter is applied before
// grouping, so the session set (and total) reflect only matching entries.
func TestAccessLogSessions_Filtering(t *testing.T) {
	ctx := context.Background()
	s := newSessionsTestStore(t)

	seedAccessLogs(t, s,
		accessLogRow("r1", "sess-1", baseTime.Add(1*time.Minute),
			withUser("alice"), withProvider("openai", "prov-openai"), withModel("gpt-5.4")),
		accessLogRow("r2", "sess-2", baseTime.Add(2*time.Minute),
			withUser("bob"), withProvider("anthropic", "prov-anthropic"), withModel("claude-haiku-4-5"),
			withDeny("llm_policy.no_authorized_provider"), withGroups("grp-ops")),
		accessLogRow("r3", "sess-3", baseTime.Add(3*time.Minute),
			withUser("alice"), withProvider("openai", "prov-openai"), withModel("gpt-5.4"),
			withGroups("grp-eng")),
	)

	filterCases := []struct {
		name    string
		filter  types.AgentNetworkAccessLogFilter
		wantIDs []string
		wantTot int64
	}{
		{
			name:    "by session id",
			filter:  types.AgentNetworkAccessLogFilter{SessionID: strp("sess-2")},
			wantIDs: []string{"sess-2"},
			wantTot: 1,
		},
		{
			name:    "by user id",
			filter:  types.AgentNetworkAccessLogFilter{UserID: strp("alice")},
			wantIDs: []string{"sess-3", "sess-1"}, // last-activity DESC
			wantTot: 2,
		},
		{
			name:    "by model",
			filter:  types.AgentNetworkAccessLogFilter{Models: []string{"claude-haiku-4-5"}},
			wantIDs: []string{"sess-2"},
			wantTot: 1,
		},
		{
			name:    "by resolved provider id",
			filter:  types.AgentNetworkAccessLogFilter{ProviderIDs: []string{"prov-openai"}},
			wantIDs: []string{"sess-3", "sess-1"},
			wantTot: 2,
		},
		{
			name:    "by decision deny",
			filter:  types.AgentNetworkAccessLogFilter{Decision: strp("deny")},
			wantIDs: []string{"sess-2"},
			wantTot: 1,
		},
		{
			name:    "by authorising group",
			filter:  types.AgentNetworkAccessLogFilter{GroupIDs: []string{"grp-eng"}},
			wantIDs: []string{"sess-3"},
			wantTot: 1,
		},
		{
			name: "by date range excludes earlier",
			filter: types.AgentNetworkAccessLogFilter{
				StartDate: tp(baseTime.Add(90 * time.Second)), // after r1 (12:01), before r2 (12:02)
			},
			wantIDs: []string{"sess-3", "sess-2"},
			wantTot: 2,
		},
	}

	for _, tc := range filterCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			sessions, total, err := s.GetAgentNetworkAccessLogSessions(ctx, store.LockingStrengthNone, testAccountID, tc.filter)
			require.NoError(t, err)
			assert.Equal(t, tc.wantTot, total, "filtered total")
			assert.Equal(t, tc.wantIDs, sessionIDs(sessions), "filtered session ids in order")
		})
	}
}

// TestAccessLogSessions_SortByCost verifies session-level aggregate sorting:
// ordering by summed cost, ascending and descending.
func TestAccessLogSessions_SortByCost(t *testing.T) {
	ctx := context.Background()
	s := newSessionsTestStore(t)

	// cheap: 0.01 total; mid: 0.05 total; pricey: 0.20 total (two entries).
	seedAccessLogs(t, s,
		accessLogRow("c1", "cheap", baseTime.Add(1*time.Minute), withTokens(1, 1, 2, 0.01)),
		accessLogRow("m1", "mid", baseTime.Add(2*time.Minute), withTokens(1, 1, 2, 0.05)),
		accessLogRow("p1", "pricey", baseTime.Add(3*time.Minute), withTokens(1, 1, 2, 0.15)),
		accessLogRow("p2", "pricey", baseTime.Add(4*time.Minute), withTokens(1, 1, 2, 0.05)),
	)

	desc, total, err := s.GetAgentNetworkAccessLogSessions(ctx, store.LockingStrengthNone, testAccountID,
		types.AgentNetworkAccessLogFilter{SortBy: "cost_usd", SortOrder: "desc"})
	require.NoError(t, err)
	require.Equal(t, int64(3), total)
	assert.Equal(t, []string{"pricey", "mid", "cheap"}, sessionIDs(desc), "descending by summed cost")

	asc, _, err := s.GetAgentNetworkAccessLogSessions(ctx, store.LockingStrengthNone, testAccountID,
		types.AgentNetworkAccessLogFilter{SortBy: "cost_usd", SortOrder: "asc"})
	require.NoError(t, err)
	assert.Equal(t, []string{"cheap", "mid", "pricey"}, sessionIDs(asc), "ascending by summed cost")
}

// strp / tp / itoa are tiny local helpers to keep the filter table terse.
func strp(s string) *string { return &s }

func tp(t time.Time) *time.Time { return &t }

func itoa(i int) string { return string(rune('0' + i)) }
