package agentnetwork

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/accesslogs"
	"github.com/netbirdio/netbird/management/server/store"
)

// newIngestTestEntry builds an agent-network reverse-proxy access-log entry whose
// LLM dimensions live in the opaque Metadata map, as the proxy ships it.
func newIngestTestEntry() *accesslogs.AccessLogEntry {
	return &accesslogs.AccessLogEntry{
		ID:           "log-1",
		AccountID:    testAccountID,
		ServiceID:    "svc-1",
		Timestamp:    time.Now().UTC(),
		Method:       "POST",
		Host:         testEndpoint,
		Path:         "/v1/chat/completions",
		StatusCode:   200,
		UserId:       "user-1",
		AgentNetwork: true,
		Metadata: map[string]string{
			metaKeyProvider:            "openai",
			metaKeyModel:               "gpt-5.4",
			metaKeyResolvedProviderID:  "prov-1",
			metaKeySessionID:           "sess-1",
			metaKeyInputTokens:         "100",
			metaKeyOutputTokens:        "50",
			metaKeyTotalTokens:         "1174",
			metaKeyCachedInputTokens:   "256",
			metaKeyCacheCreationTokens: "768",
			metaKeyCostUSDInput:        "0.0071",
			metaKeyCostUSDCachedInput:  "0.0009",
			metaKeyCostUSDCacheCreate:  "0.0020",
			metaKeyCostUSDOutput:       "0.0023",
			metaKeyStream:              "true",
			metaKeyRequestPrompt:       "hello",
			metaKeyResponseCompletion:  "world",
			// repeated id must be de-duplicated before the group rows insert.
			metaKeyAuthorisingGroups: "grp-eng,grp-eng,grp-ops",
		},
	}
}

// TestIngestAccessLog_RealStore_LogCollectionOff persists the usage ledger
// unconditionally but skips the full access-log row when the account hasn't
// opted into log collection.
func TestIngestAccessLog_RealStore_LogCollectionOff(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	defer cleanup()

	settings := newSynthTestSettings()
	settings.EnableLogCollection = false
	require.NoError(t, s.SaveAgentNetworkSettings(ctx, settings))

	require.NoError(t, IngestAccessLog(ctx, s, newIngestTestEntry()))

	usage, err := s.GetAgentNetworkUsageRows(ctx, store.LockingStrengthNone, testAccountID, types.AgentNetworkAccessLogFilter{})
	require.NoError(t, err)
	require.Len(t, usage, 1, "usage row must be written even with log collection off")
	assert.Equal(t, int64(100), usage[0].InputTokens, "input tokens must round-trip from metadata")
	assert.Equal(t, int64(50), usage[0].OutputTokens, "output tokens must round-trip from metadata")
	assert.Equal(t, int64(256), usage[0].CachedInputTokens, "cache-read tokens must round-trip from metadata")
	assert.Equal(t, int64(768), usage[0].CacheCreationTokens, "cache-write tokens must round-trip from metadata")
	// The per-bucket breakdown is the only cost state stored, and must survive
	// the write/read cycle as real columns — usage rows are the only cost
	// record for accounts with log collection off, so a dropped column here
	// loses the split permanently.
	assert.InDelta(t, 0.0071, usage[0].InputCostUSD, 1e-9, "input cost must round-trip from metadata")
	assert.InDelta(t, 0.0009, usage[0].CachedInputCostUSD, 1e-9, "cache-read cost must round-trip from metadata")
	assert.InDelta(t, 0.0020, usage[0].CacheCreationCostUSD, 1e-9, "cache-write cost must round-trip from metadata")
	assert.InDelta(t, 0.0023, usage[0].OutputCostUSD, 1e-9, "output cost must round-trip from metadata")
	// Aggregates are derived from the stored columns, never stored themselves.
	assert.InDelta(t, 0.0123, usage[0].TotalCostUSD(), 1e-9, "total is derived from the stored buckets")
	assert.InDelta(t, 0.0029, usage[0].CacheCostUSD(), 1e-9, "cache cost is derived from the two cache buckets")

	logs, _, err := s.GetAgentNetworkAccessLogs(ctx, store.LockingStrengthNone, testAccountID, types.AgentNetworkAccessLogFilter{})
	require.NoError(t, err)
	assert.Empty(t, logs, "full access-log row must be skipped while log collection is off")
}

// TestIngestAccessLog_RealStore_LogCollectionOn writes both the usage ledger and
// the full access-log row once the account opts in, carrying the request detail
// and prompt through.
func TestIngestAccessLog_RealStore_LogCollectionOn(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	defer cleanup()

	settings := newSynthTestSettings()
	settings.EnableLogCollection = true
	require.NoError(t, s.SaveAgentNetworkSettings(ctx, settings))

	require.NoError(t, IngestAccessLog(ctx, s, newIngestTestEntry()))

	usage, err := s.GetAgentNetworkUsageRows(ctx, store.LockingStrengthNone, testAccountID, types.AgentNetworkAccessLogFilter{})
	require.NoError(t, err)
	require.Len(t, usage, 1, "usage row must be written when log collection is on")

	logs, total, err := s.GetAgentNetworkAccessLogs(ctx, store.LockingStrengthNone, testAccountID, types.AgentNetworkAccessLogFilter{})
	require.NoError(t, err)
	require.Equal(t, int64(1), total, "exactly one access-log row expected")
	require.Len(t, logs, 1, "full access-log row must be written when log collection is on")
	assert.Equal(t, "gpt-5.4", logs[0].Model, "model must flatten from metadata")
	assert.Equal(t, int64(256), logs[0].CachedInputTokens, "cache-read tokens must flatten from metadata")
	assert.Equal(t, int64(768), logs[0].CacheCreationTokens, "cache-write tokens must flatten from metadata")
	assert.InDelta(t, 0.0029, logs[0].CacheCostUSD(), 1e-9, "cache cost is derived from the two cache buckets")
	assert.InDelta(t, 0.0123, logs[0].TotalCostUSD(), 1e-9, "total is derived from the stored buckets")
	assert.InDelta(t, 0.0071, logs[0].InputCostUSD, 1e-9, "input cost must flatten from metadata")
	assert.InDelta(t, 0.0009, logs[0].CachedInputCostUSD, 1e-9, "cache-read cost must flatten from metadata")
	assert.InDelta(t, 0.0020, logs[0].CacheCreationCostUSD, 1e-9, "cache-write cost must flatten from metadata")
	assert.InDelta(t, 0.0023, logs[0].OutputCostUSD, 1e-9, "output cost must flatten from metadata")
	assert.Equal(t, "hello", logs[0].RequestPrompt, "prompt must be retained when log collection is on")
	assert.Equal(t, "world", logs[0].ResponseCompletion, "completion must be retained when log collection is on")
	assert.True(t, logs[0].Stream, "stream flag must flatten from metadata")
}

func TestParseGroupCSV_DedupAndTrim(t *testing.T) {
	assert.Nil(t, parseGroupCSV(""), "empty CSV yields no groups")
	assert.Equal(t, []string{"a", "b"}, parseGroupCSV(" a , b , a ,"),
		"group CSV must trim, drop blanks, and de-duplicate preserving first-seen order")
}

func TestParseMetaInt_ClampsNegativeAndJunk(t *testing.T) {
	meta := map[string]string{"ok": " 42 ", "neg": "-5", "junk": "abc"}
	assert.Equal(t, int64(42), parseMetaInt(meta, "ok"), "valid count parses with surrounding space trimmed")
	assert.Equal(t, int64(0), parseMetaInt(meta, "neg"), "negative count clamps to 0")
	assert.Equal(t, int64(0), parseMetaInt(meta, "junk"), "unparseable count clamps to 0")
	assert.Equal(t, int64(0), parseMetaInt(meta, "missing"), "missing key clamps to 0")
}

func TestParseMetaFloat_ClampsNegativeInfAndJunk(t *testing.T) {
	meta := map[string]string{"ok": "1.5", "neg": "-1", "inf": "Inf", "junk": "x"}
	assert.InDelta(t, 1.5, parseMetaFloat(meta, "ok"), 1e-9, "valid cost parses")
	assert.Equal(t, float64(0), parseMetaFloat(meta, "neg"), "negative cost clamps to 0")
	assert.Equal(t, float64(0), parseMetaFloat(meta, "inf"), "non-finite cost clamps to 0")
	assert.Equal(t, float64(0), parseMetaFloat(meta, "junk"), "unparseable cost clamps to 0")
}
