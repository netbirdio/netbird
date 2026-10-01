package builtin_test

import (
	"context"
	"net"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	mgmtgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork"
	agentNetworkTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/server/store"
	nbtypes "github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_limit_check"
	"github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_limit_record"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// chainIntegrationFixture wires the BOTH new agent-network
// middlewares against a live in-process management stack: real
// sqlite store + real Manager + real gRPC server. The proxy chain
// framework itself isn't constructed (its dispatcher / accumulator /
// metadata gate are tested separately); we exercise the middleware
// pair as the proxy runtime would, by invoking each with a crafted
// Input and asserting the wire path between them.
//
// This is the regression cover for item 16 in the design review:
// real LLM request → cost stamped → consumption row in the table.
type chainIntegrationFixture struct {
	store    store.Store
	manager  agentnetwork.Manager
	gatecase *llm_limit_check.Middleware
	recorder *llm_limit_record.Middleware
}

func newChainIntegration(t *testing.T) *chainIntegrationFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("sqlite store not properly supported on Windows yet")
	}
	t.Setenv("NETBIRD_STORE_ENGINE", string(nbtypes.SqliteStoreEngine))

	st, cleanUp, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanUp)

	manager := agentnetwork.NewManager(st, nil, nil, nil)

	server := &mgmtgrpc.ProxyServiceServer{}
	server.SetAgentNetworkLimitsService(manager)

	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	proto.RegisterProxyServiceServer(srv, server)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	mgmtClient := proto.NewProxyServiceClient(conn)
	return &chainIntegrationFixture{
		store:    st,
		manager:  manager,
		gatecase: llm_limit_check.New(mgmtClient, nil),
		recorder: llm_limit_record.New(mgmtClient, nil),
	}
}

// chainInput builds a middleware Input that mirrors what the proxy
// framework would synthesise for a tunnel-peer LLM request. The
// gate consumes the resolved provider id from upstream metadata
// (set by llm_router); the recorder consumes the attribution
// metadata stamped by the gate plus tokens / cost from
// llm_response_parser + cost_meter.
func chainInput(account, user, group, providerID string, requestMeta []middleware.KV) *middleware.Input {
	_ = providerID // packed into requestMeta by the caller as KeyLLMResolvedProviderID
	return &middleware.Input{
		AccountID:  account,
		UserID:     user,
		UserGroups: []string{group},
		Metadata:   requestMeta,
	}
}

// chainCapPolicy builds a tight token-cap policy fixture for the
// chain integration tests. Inlined here (rather than imported) because
// the equivalent helper in the management gRPC package is unexported
// and this is a different package boundary.
func chainCapPolicy(id, account string, sourceGroups []string, providerID string, tokenCap, windowSec int64) *agentNetworkTypes.Policy {
	return &agentNetworkTypes.Policy{
		ID:                     id,
		AccountID:              account,
		Enabled:                true,
		Name:                   id,
		SourceGroups:           sourceGroups,
		DestinationProviderIDs: []string{providerID},
		Limits: agentNetworkTypes.PolicyLimits{
			TokenLimit: agentNetworkTypes.PolicyTokenLimit{
				Enabled:       true,
				GroupCap:      tokenCap,
				WindowSeconds: windowSec,
			},
		},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
}

// TestChain_AllowPath_StampsAttributionAndRecordsCounter walks the
// full happy path: gate calls CheckLLMPolicyLimits → stamps
// attribution metadata → recorder reads metadata + tokens / cost →
// calls RecordLLMUsage → counters land in sqlite. Asserting on the
// store at the end proves every leg of the wire works together,
// not just each leg in isolation (which the unit tests already cover).
func TestChain_AllowPath_StampsAttributionAndRecordsCounter(t *testing.T) {
	f := newChainIntegration(t)

	const account = "acc-1"
	const user = "user-bob"
	const group = "grp-engineers"
	const provider = "prov-1"

	// Seed a policy with token + budget caps; both halves carry
	// real ceilings so the request stays within headroom.
	require.NoError(t, f.store.SaveAgentNetworkPolicy(context.Background(),
		chainCapPolicy("pol-1", account, []string{group}, provider, 10_000, 86_400)))

	// ── Stage 1 — gate: pre-flight check ──────────────────────
	gateIn := chainInput(account, user, group, provider, []middleware.KV{
		{Key: middleware.KeyLLMResolvedProviderID, Value: provider},
		{Key: middleware.KeyLLMModel, Value: "gpt-4o"},
	})
	gateOut, err := f.gatecase.Invoke(context.Background(), gateIn)
	require.NoError(t, err)
	require.Equal(t, middleware.DecisionAllow, gateOut.Decision, "fresh policy must allow")

	// Verify attribution metadata was stamped — the recorder
	// depends on these keys.
	metaMap := map[string]string{}
	for _, kv := range gateOut.Metadata {
		metaMap[kv.Key] = kv.Value
	}
	assert.Equal(t, "pol-1", metaMap[middleware.KeyLLMSelectedPolicyID])
	assert.Equal(t, group, metaMap[middleware.KeyLLMAttributionGroupID])
	assert.Equal(t, "86400", metaMap[middleware.KeyLLMAttributionWindowS])

	// ── Stage 2 — recorder: post-flight write ─────────────────
	// Build the response-leg Input the framework would synthesise
	// for the recorder: gate's emitted attribution metadata + the
	// tokens / cost stamped by llm_response_parser + cost_meter.
	const tokensIn = int64(123)
	const tokensOut = int64(45)
	const costUSD = 0.0042
	recordIn := chainInput(account, user, group, provider, append([]middleware.KV{},
		gateOut.Metadata...))
	recordIn.Metadata = append(recordIn.Metadata,
		middleware.KV{Key: middleware.KeyLLMInputTokens, Value: strconv.FormatInt(tokensIn, 10)},
		middleware.KV{Key: middleware.KeyLLMOutputTokens, Value: strconv.FormatInt(tokensOut, 10)},
		middleware.KV{Key: middleware.KeyCostUSDTotal, Value: strconv.FormatFloat(costUSD, 'f', 6, 64)},
	)
	recordOut, err := f.recorder.Invoke(context.Background(), recordIn)
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionAllow, recordOut.Decision, "recorder always allows; its only side effect is the counter write")

	// ── Stage 3 — assert state in sqlite ──────────────────────
	windowStart := agentNetworkTypes.WindowStart(time.Now(), 86_400)
	userRow, err := f.store.GetAgentNetworkConsumption(
		context.Background(), store.LockingStrengthNone, account,
		agentNetworkTypes.DimensionUser, user, int64(86_400), windowStart,
	)
	require.NoError(t, err)
	assert.Equal(t, tokensIn, userRow.TokensInput, "user counter must hold the input tokens the recorder posted")
	assert.Equal(t, tokensOut, userRow.TokensOutput)
	assert.InDelta(t, costUSD, userRow.CostUSD, 1e-6)

	groupRow, err := f.store.GetAgentNetworkConsumption(
		context.Background(), store.LockingStrengthNone, account,
		agentNetworkTypes.DimensionGroup, group, int64(86_400), windowStart,
	)
	require.NoError(t, err)
	assert.Equal(t, tokensIn, groupRow.TokensInput, "group counter mirrors the user counter — single Record posts both dims")
}

// TestChain_DenyPath_GateRejectsAndNoConsumptionWritten covers the
// negative side: when the gate denies, the recorder is never
// invoked (the proxy framework short-circuits on Decision=Deny).
// We assert no consumption row materialises after the gate-deny
// path, even though the test technically calls the recorder
// afterwards — the recorder must skip on missing attribution
// metadata so the framework's short-circuit isn't load-bearing for
// data integrity.
func TestChain_DenyPath_GateRejectsAndNoConsumptionWritten(t *testing.T) {
	f := newChainIntegration(t)

	const account = "acc-1"
	const user = "user-bob"
	const group = "grp-tight"
	const provider = "prov-1"

	policy := chainCapPolicy("pol-tight", account, []string{group}, provider, 100, 86_400)
	require.NoError(t, f.store.SaveAgentNetworkPolicy(context.Background(), policy))

	// Pre-burn the counter to the cap so the gate denies.
	require.NoError(t, f.store.IncrementAgentNetworkConsumption(
		context.Background(), account,
		agentNetworkTypes.DimensionGroup, group, int64(86_400),
		agentNetworkTypes.WindowStart(time.Now(), 86_400),
		100, 0, 0,
	))

	gateOut, err := f.gatecase.Invoke(context.Background(), chainInput(account, user, group, provider,
		[]middleware.KV{
			{Key: middleware.KeyLLMResolvedProviderID, Value: provider},
			{Key: middleware.KeyLLMModel, Value: "gpt-4o"},
		},
	))
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionDeny, gateOut.Decision, "policy at-cap must deny on the gate")
	require.NotNil(t, gateOut.DenyReason)
	assert.Equal(t, "llm_policy.token_cap_exceeded", gateOut.DenyReason.Code)

	// On deny, the gate emits no attribution metadata. If the
	// proxy framework still invokes the recorder (defense in
	// depth), the recorder's "no attribution window = skip" guard
	// prevents a phantom counter increment.
	recordOut, err := f.recorder.Invoke(context.Background(), chainInput(account, user, group, provider,
		gateOut.Metadata, // no llm.attribution_window_seconds stamped
	))
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionAllow, recordOut.Decision)

	// The pre-burned 100 tokens are the only counter movement —
	// the recorder must NOT have added a fresh row for the user
	// dimension on this denied request.
	windowStart := agentNetworkTypes.WindowStart(time.Now(), 86_400)
	userRow, err := f.store.GetAgentNetworkConsumption(
		context.Background(), store.LockingStrengthNone, account,
		agentNetworkTypes.DimensionUser, user, int64(86_400), windowStart,
	)
	require.NoError(t, err)
	assert.Zero(t, userRow.TokensInput, "user dimension must not gain tokens from a denied request — recorder skip is the safety net")
}

// TestChain_CapExhaustTransition exercises the allow→deny boundary
// the operator cares most about: a request just under cap allows
// AND records, the next request post-record at-cap denies. This is
// the same lifecycle 50-grpc-allow-record-deny.sh runs in bash, but
// against the actual middleware pair rather than the smoke binary
// driving the gRPC RPCs directly.
func TestChain_CapExhaustTransition(t *testing.T) {
	f := newChainIntegration(t)

	const account = "acc-1"
	const user = "user-alice"
	const group = "grp-cap-edge"
	const provider = "prov-1"
	const tightCap = int64(100)

	require.NoError(t, f.store.SaveAgentNetworkPolicy(context.Background(),
		chainCapPolicy("pol-edge", account, []string{group}, provider, tightCap, 86_400)))

	// Pre-burn 99 tokens so we're at the very edge.
	require.NoError(t, f.store.IncrementAgentNetworkConsumption(
		context.Background(), account,
		agentNetworkTypes.DimensionGroup, group, int64(86_400),
		agentNetworkTypes.WindowStart(time.Now(), 86_400),
		99, 0, 0,
	))

	// Gate at 99/100 — must allow (one token of headroom).
	gateOut, err := f.gatecase.Invoke(context.Background(), chainInput(account, user, group, provider,
		[]middleware.KV{
			{Key: middleware.KeyLLMResolvedProviderID, Value: provider},
			{Key: middleware.KeyLLMModel, Value: "gpt-4o"},
		},
	))
	require.NoError(t, err)
	require.Equal(t, middleware.DecisionAllow, gateOut.Decision, "99/100 must allow — one token of headroom")

	// Record one more input token — pushes us to 100/100.
	recordIn := chainInput(account, user, group, provider, append([]middleware.KV{},
		gateOut.Metadata...))
	recordIn.Metadata = append(recordIn.Metadata,
		middleware.KV{Key: middleware.KeyLLMInputTokens, Value: "1"},
		middleware.KV{Key: middleware.KeyLLMOutputTokens, Value: "0"},
		middleware.KV{Key: middleware.KeyCostUSDTotal, Value: "0.000001"},
	)
	_, err = f.recorder.Invoke(context.Background(), recordIn)
	require.NoError(t, err)

	// Next gate call must deny — counter is exactly at cap.
	gateOut2, err := f.gatecase.Invoke(context.Background(), chainInput(account, user, group, provider,
		[]middleware.KV{
			{Key: middleware.KeyLLMResolvedProviderID, Value: provider},
			{Key: middleware.KeyLLMModel, Value: "gpt-4o"},
		},
	))
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionDeny, gateOut2.Decision,
		"once recorder pushed the group counter to 100/100, the next gate call must deny — allow→deny transition is the operator-visible product semantic")
	require.NotNil(t, gateOut2.DenyReason)
	assert.Equal(t, "llm_policy.token_cap_exceeded", gateOut2.DenyReason.Code)
}
