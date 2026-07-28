package llm_limit_check

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

// fakeMgmt is a minimal builtin.MgmtClient stub that lets the test
// drive CheckLLMPolicyLimits responses without a real gRPC dial.
type fakeMgmt struct {
	checkResp *proto.CheckLLMPolicyLimitsResponse
	checkErr  error
	checkReq  *proto.CheckLLMPolicyLimitsRequest
}

func (f *fakeMgmt) CheckLLMPolicyLimits(_ context.Context, in *proto.CheckLLMPolicyLimitsRequest, _ ...grpc.CallOption) (*proto.CheckLLMPolicyLimitsResponse, error) {
	f.checkReq = in
	return f.checkResp, f.checkErr
}

func (f *fakeMgmt) RecordLLMUsage(_ context.Context, _ *proto.RecordLLMUsageRequest, _ ...grpc.CallOption) (*proto.RecordLLMUsageResponse, error) {
	return &proto.RecordLLMUsageResponse{}, nil
}

func runInvoke(t *testing.T, m *Middleware, in *middleware.Input) *middleware.Output {
	t.Helper()
	out, err := m.Invoke(context.Background(), in)
	require.NoError(t, err, "Invoke must not propagate transport errors")
	require.NotNil(t, out, "Invoke must always return an Output")
	return out
}

// TestInvoke_AllowStampsAttributionMetadata covers the happy path:
// management returns an allow decision with selected_policy_id +
// attribution_group_id + window_seconds, the middleware emits all three
// onto the metadata bag so the post-flight llm_limit_record
// middleware has everything it needs to tick the right counter.
func TestInvoke_AllowStampsAttributionMetadata(t *testing.T) {
	mgmt := &fakeMgmt{
		checkResp: &proto.CheckLLMPolicyLimitsResponse{
			Decision:           "allow",
			SelectedPolicyId:   "pol-X",
			AttributionGroupId: "grp-engineers",
			WindowSeconds:      86_400,
		},
	}
	m := New(mgmt, nil)

	out := runInvoke(t, m, &middleware.Input{
		AccountID:  "acc-1",
		UserID:     "user-bob",
		UserGroups: []string{"grp-engineers"},
		Metadata: []middleware.KV{
			{Key: middleware.KeyLLMResolvedProviderID, Value: "prov-1"},
			{Key: middleware.KeyLLMModel, Value: "gpt-4o"},
		},
	})

	assert.Equal(t, middleware.DecisionAllow, out.Decision)
	assert.Equal(t, "acc-1", mgmt.checkReq.GetAccountId(), "account_id must round-trip onto the RPC")
	assert.Equal(t, "user-bob", mgmt.checkReq.GetUserId())
	assert.Equal(t, []string{"grp-engineers"}, mgmt.checkReq.GetGroupIds())
	assert.Equal(t, "prov-1", mgmt.checkReq.GetProviderId(), "resolved provider id must come from metadata")
	assert.Equal(t, "gpt-4o", mgmt.checkReq.GetModel(), "model must come from metadata")

	want := map[string]string{
		middleware.KeyLLMPolicyDecision:     "allow",
		middleware.KeyLLMSelectedPolicyID:   "pol-X",
		middleware.KeyLLMAttributionGroupID: "grp-engineers",
		middleware.KeyLLMAttributionWindowS: "86400",
	}
	got := map[string]string{}
	for _, kv := range out.Metadata {
		got[kv.Key] = kv.Value
	}
	assert.Equal(t, want, got, "attribution metadata must land on the bag for the response leg to consume")
}

// TestInvoke_DenyConvertsToProxyDeny proves the deny envelope round-
// trips: management's deny code becomes the proxy framework's deny
// payload at status 403, and the deny reason text is preserved so
// operators can debug from the access log.
func TestInvoke_DenyConvertsToProxyDeny(t *testing.T) {
	mgmt := &fakeMgmt{
		checkResp: &proto.CheckLLMPolicyLimitsResponse{
			Decision:   "deny",
			DenyCode:   "llm_policy.token_cap_exceeded",
			DenyReason: "group token cap exhausted on policy pol-X (used 1000 of 1000)",
		},
	}
	m := New(mgmt, nil)

	out := runInvoke(t, m, &middleware.Input{
		AccountID:  "acc-1",
		UserGroups: []string{"grp-engineers"},
		Metadata:   []middleware.KV{{Key: middleware.KeyLLMResolvedProviderID, Value: "prov-1"}},
	})

	assert.Equal(t, middleware.DecisionDeny, out.Decision)
	assert.Equal(t, 403, out.DenyStatus, "policy denials are 403 — same as llm_router's")
	require.NotNil(t, out.DenyReason, "deny envelope must carry a reason payload")
	assert.Equal(t, "llm_policy.token_cap_exceeded", out.DenyReason.Code, "canonical deny code surfaces to the caller")
	// The public message must stay generic: the management reason names
	// internal quota detail (used/cap, rule id) that must not leak.
	assert.Equal(t, "LLM policy limit exceeded", out.DenyReason.Message, "public deny message must be generic")
	assert.NotContains(t, out.DenyReason.Message, "exhausted", "internal quota detail must not reach the caller")
	assert.NotContains(t, out.DenyReason.Message, "1000", "internal cap numbers must not reach the caller")
}

// TestInvoke_NoMgmtClientPassesThrough proves the partial-wiring
// safety: a middleware constructed without a management client
// allows every request without attribution. This makes a half-set-up
// environment indistinguishable from "no enforcement" rather than
// breaking the chain.
func TestInvoke_NoMgmtClientPassesThrough(t *testing.T) {
	m := New(nil, nil)

	out := runInvoke(t, m, &middleware.Input{
		AccountID:  "acc-1",
		UserGroups: []string{"grp-engineers"},
		Metadata:   []middleware.KV{{Key: middleware.KeyLLMResolvedProviderID, Value: "prov-1"}},
	})

	assert.Equal(t, middleware.DecisionAllow, out.Decision)
	for _, kv := range out.Metadata {
		assert.NotEqual(t, middleware.KeyLLMSelectedPolicyID, kv.Key,
			"no mgmt client = no attribution metadata; record middleware then skips its write")
	}
}

// TestInvoke_NoResolvedProviderPassesThrough covers the defensive
// path: when llm_router didn't set llm.resolved_provider_id (which
// only happens on the deny side of llm_router), the gate must NOT
// stack a second deny on top — pass through and let the upstream
// deny stand.
func TestInvoke_NoResolvedProviderPassesThrough(t *testing.T) {
	m := New(&fakeMgmt{}, nil)

	out := runInvoke(t, m, &middleware.Input{
		AccountID: "acc-1",
		Metadata:  []middleware.KV{},
	})

	assert.Equal(t, middleware.DecisionAllow, out.Decision,
		"no resolved provider = the gate has nothing to check; never deny on top of an upstream allow")
}

// TestInvoke_RPCErrorFailsOpen proves the fail-open contract: a
// transport error from management does NOT deny the request. v1
// trades enforcement strictness for availability — an unreachable
// management server otherwise turns into a total LLM outage.
func TestInvoke_RPCErrorFailsOpen(t *testing.T) {
	m := New(&fakeMgmt{checkErr: errors.New("connection refused")}, nil)

	out := runInvoke(t, m, &middleware.Input{
		AccountID:  "acc-1",
		UserGroups: []string{"grp-engineers"},
		Metadata:   []middleware.KV{{Key: middleware.KeyLLMResolvedProviderID, Value: "prov-1"}},
	})

	assert.Equal(t, middleware.DecisionAllow, out.Decision,
		"transport errors must not cascade into total LLM outages — operators audit via access log")
}

// TestMetadataKeys_Allowlist locks the closed set this middleware can
// emit. The accumulator drops anything outside this list; adding a
// new emission means updating both the slice and this test.
func TestMetadataKeys_Allowlist(t *testing.T) {
	keys := New(nil, nil).MetadataKeys()
	want := []string{
		middleware.KeyLLMSelectedPolicyID,
		middleware.KeyLLMAttributionGroupID,
		middleware.KeyLLMAttributionWindowS,
		middleware.KeyLLMPolicyDecision,
		middleware.KeyLLMPolicyReason,
	}
	assert.ElementsMatch(t, want, keys)
}
