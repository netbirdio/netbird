package llm_limit_record

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type fakeMgmt struct {
	recordReq    *proto.RecordLLMUsageRequest
	recordCalled bool
	recordErr    error
}

func (f *fakeMgmt) CheckLLMPolicyLimits(_ context.Context, _ *proto.CheckLLMPolicyLimitsRequest, _ ...grpc.CallOption) (*proto.CheckLLMPolicyLimitsResponse, error) {
	return &proto.CheckLLMPolicyLimitsResponse{Decision: "allow"}, nil
}

func (f *fakeMgmt) RecordLLMUsage(_ context.Context, in *proto.RecordLLMUsageRequest, _ ...grpc.CallOption) (*proto.RecordLLMUsageResponse, error) {
	f.recordCalled = true
	f.recordReq = in
	return &proto.RecordLLMUsageResponse{}, f.recordErr
}

func runInvoke(t *testing.T, m *Middleware, in *middleware.Input) *middleware.Output {
	t.Helper()
	out, err := m.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.NotNil(t, out)
	return out
}

// TestInvoke_PostsAttributionWithTokensAndCost covers the happy path:
// when the request leg stamped attribution + the upstream parsers
// stamped tokens + cost, the post-flight call carries every field
// through to RecordLLMUsage.
func TestInvoke_PostsAttributionWithTokensAndCost(t *testing.T) {
	mgmt := &fakeMgmt{}
	m := New(mgmt, nil)

	out := runInvoke(t, m, &middleware.Input{
		AccountID: "acc-1",
		UserID:    "user-bob",
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMAttributionGroupID, Value: "grp-engineers"},
			{Key: middleware.KeyLLMAttributionWindowS, Value: "86400"},
			{Key: middleware.KeyLLMInputTokens, Value: "150"},
			{Key: middleware.KeyLLMOutputTokens, Value: "75"},
			{Key: middleware.KeyCostUSDTotal, Value: "0.0125"},
		},
	})

	assert.Equal(t, middleware.DecisionAllow, out.Decision)
	require.True(t, mgmt.recordCalled, "record must be invoked when attribution + usage are both present")
	assert.Equal(t, "acc-1", mgmt.recordReq.GetAccountId())
	assert.Equal(t, "user-bob", mgmt.recordReq.GetUserId())
	assert.Equal(t, "grp-engineers", mgmt.recordReq.GetGroupId())
	assert.Equal(t, int64(86_400), mgmt.recordReq.GetWindowSeconds())
	assert.Equal(t, int64(150), mgmt.recordReq.GetTokensInput())
	assert.Equal(t, int64(75), mgmt.recordReq.GetTokensOutput())
	assert.InDelta(t, 0.0125, mgmt.recordReq.GetCostUsd(), 1e-9)
}

// TestInvoke_NoAttributionWindowStillRecordsForAccountFanOut proves the
// catch-all-allow path now STILL records (window 0): account-level budget
// rules live in their own windows and bind independently of policies, so the
// management side needs the post-flight call even when no policy cap applied.
// The full group set is forwarded so the account fan-out can attribute.
func TestInvoke_NoAttributionWindowStillRecordsForAccountFanOut(t *testing.T) {
	mgmt := &fakeMgmt{}
	m := New(mgmt, nil)

	runInvoke(t, m, &middleware.Input{
		AccountID:  "acc-1",
		UserID:     "user-bob",
		UserGroups: []string{"grp-eng", "grp-oncall"},
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMInputTokens, Value: "150"},
			{Key: middleware.KeyLLMOutputTokens, Value: "75"},
			{Key: middleware.KeyCostUSDTotal, Value: "0.0125"},
		},
	})

	require.True(t, mgmt.recordCalled, "must record even without a policy window so account budgets accumulate")
	assert.Equal(t, int64(0), mgmt.recordReq.GetWindowSeconds(), "no policy window is forwarded as 0")
	assert.Empty(t, mgmt.recordReq.GetGroupId(), "no attribution group without a policy")
	assert.Equal(t, []string{"grp-eng", "grp-oncall"}, mgmt.recordReq.GetGroupIds(), "full group set must be forwarded for the account fan-out")
}

// TestInvoke_NoPrincipalSkipsRecord proves that with neither a user nor any
// groups there is nothing to attribute, so the write is skipped.
func TestInvoke_NoPrincipalSkipsRecord(t *testing.T) {
	mgmt := &fakeMgmt{}
	m := New(mgmt, nil)

	runInvoke(t, m, &middleware.Input{
		AccountID: "acc-1",
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMInputTokens, Value: "150"},
			{Key: middleware.KeyCostUSDTotal, Value: "0.0125"},
		},
	})

	assert.False(t, mgmt.recordCalled, "no user and no groups = nothing to attribute")
}

// TestInvoke_ZeroUsageSkipsRecord proves the no-usage-no-write path:
// when the upstream parser couldn't extract token counts (streaming,
// malformed body, …), skipping the write keeps phantom rows out of
// the consumption table.
func TestInvoke_ZeroUsageSkipsRecord(t *testing.T) {
	mgmt := &fakeMgmt{}
	m := New(mgmt, nil)

	runInvoke(t, m, &middleware.Input{
		AccountID: "acc-1",
		UserID:    "user-bob",
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMAttributionGroupID, Value: "grp-engineers"},
			{Key: middleware.KeyLLMAttributionWindowS, Value: "86400"},
		},
	})

	assert.False(t, mgmt.recordCalled, "zero tokens AND zero cost = nothing to record; an upstream parse miss must not surface as a row")
}

// TestInvoke_RPCErrorIsSwallowed proves the post-flight isolation
// contract: management errors must NOT cascade back to the proxy
// because the upstream response has already been served — failing
// the chain at this point would corrupt the response. Errors are
// logged at debug level and swallowed.
func TestInvoke_RPCErrorIsSwallowed(t *testing.T) {
	mgmt := &fakeMgmt{recordErr: errors.New("management down")}
	m := New(mgmt, nil)

	out := runInvoke(t, m, &middleware.Input{
		AccountID: "acc-1",
		UserID:    "user-bob",
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMAttributionGroupID, Value: "grp-engineers"},
			{Key: middleware.KeyLLMAttributionWindowS, Value: "86400"},
			{Key: middleware.KeyLLMInputTokens, Value: "100"},
		},
	})

	assert.Equal(t, middleware.DecisionAllow, out.Decision,
		"a record failure must not surface — the upstream response is already on the wire")
}

// TestInvoke_NoMgmtClientPassesThrough mirrors the gate's safety
// contract: a partial wiring is consistent. No mgmt client = silent
// skip rather than an unhandled nil-deref.
func TestInvoke_NoMgmtClientPassesThrough(t *testing.T) {
	m := New(nil, nil)
	out := runInvoke(t, m, &middleware.Input{
		AccountID: "acc-1",
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMAttributionGroupID, Value: "grp-engineers"},
			{Key: middleware.KeyLLMAttributionWindowS, Value: "86400"},
			{Key: middleware.KeyLLMInputTokens, Value: "100"},
		},
	})
	assert.Equal(t, middleware.DecisionAllow, out.Decision)
}

// TestInvoke_NoIdentitySkipsRecord covers a defensive guard: stamped
// attribution but no user_id AND no group_id (shouldn't happen, but
// possible if the gate ever changes shape) must not write a row keyed
// on empty dimension ids.
func TestInvoke_NoIdentitySkipsRecord(t *testing.T) {
	mgmt := &fakeMgmt{}
	m := New(mgmt, nil)

	runInvoke(t, m, &middleware.Input{
		AccountID: "acc-1",
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMAttributionWindowS, Value: "86400"},
			{Key: middleware.KeyLLMInputTokens, Value: "100"},
		},
	})

	assert.False(t, mgmt.recordCalled,
		"empty user + group identity must skip the write — never key on empty dimension ids")
}
