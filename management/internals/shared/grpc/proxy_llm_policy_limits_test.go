package grpc

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// fakeAgentNetworkLimits is a minimal AgentNetworkLimitsService double that
// records the PolicySelectionInput it was invoked with and returns a
// pre-programmed result, so tests can assert exactly what CheckLLMPolicyLimits
// forwards to the selector.
type fakeAgentNetworkLimits struct {
	gotInput agentnetwork.PolicySelectionInput
	result   *agentnetwork.PolicySelectionResult
	err      error
}

func (f *fakeAgentNetworkLimits) SelectPolicyForRequest(_ context.Context, in agentnetwork.PolicySelectionInput) (*agentnetwork.PolicySelectionResult, error) {
	f.gotInput = in
	if f.err != nil {
		return nil, f.err
	}
	return f.result, nil
}

func (f *fakeAgentNetworkLimits) RecordUsage(_ context.Context, _ agentnetwork.RecordUsageInput) error {
	return nil
}

// TestCheckLLMPolicyLimits_ForwardsModelToSelector proves the wiring added in
// this PR: the model the proxy extracted from the request body must reach the
// selector's PolicySelectionInput.Model unchanged, alongside the pre-existing
// account/user/group/provider fields.
func TestCheckLLMPolicyLimits_ForwardsModelToSelector(t *testing.T) {
	fake := &fakeAgentNetworkLimits{result: &agentnetwork.PolicySelectionResult{Allow: true, SelectedPolicyID: "pol-1"}}
	s := &ProxyServiceServer{}
	s.SetAgentNetworkLimitsService(fake)

	req := &proto.CheckLLMPolicyLimitsRequest{
		AccountId:  "acc-1",
		UserId:     "user-1",
		GroupIds:   []string{"grp-a", "grp-b"},
		ProviderId: "prov-1",
		Model:      "claude-opus-4",
	}

	resp, err := s.CheckLLMPolicyLimits(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, "acc-1", fake.gotInput.AccountID)
	assert.Equal(t, "user-1", fake.gotInput.UserID)
	assert.Equal(t, []string{"grp-a", "grp-b"}, fake.gotInput.GroupIDs)
	assert.Equal(t, "prov-1", fake.gotInput.ProviderID)
	assert.Equal(t, "claude-opus-4", fake.gotInput.Model,
		"the request's model must be forwarded to the selector's PolicySelectionInput")
}

// TestCheckLLMPolicyLimits_EmptyModelForwardedAsEmpty proves an
// undetermined model (empty string) is forwarded as-is rather than defaulted
// to some sentinel — the selector is the one that decides how to treat it
// (fail closed when a restriction applies).
func TestCheckLLMPolicyLimits_EmptyModelForwardedAsEmpty(t *testing.T) {
	fake := &fakeAgentNetworkLimits{result: &agentnetwork.PolicySelectionResult{Allow: true}}
	s := &ProxyServiceServer{}
	s.SetAgentNetworkLimitsService(fake)

	req := &proto.CheckLLMPolicyLimitsRequest{
		AccountId:  "acc-1",
		ProviderId: "prov-1",
	}

	_, err := s.CheckLLMPolicyLimits(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "", fake.gotInput.Model, "an absent model must be forwarded as empty, not fabricated")
}

// TestCheckLLMPolicyLimits_DenyResponseCarriesModelBlockedCode proves the deny
// envelope surfaces the model-allowlist deny code + reason end to end through
// the gRPC response, matching the proxy guardrail's code so both layers agree.
func TestCheckLLMPolicyLimits_DenyResponseCarriesModelBlockedCode(t *testing.T) {
	fake := &fakeAgentNetworkLimits{result: &agentnetwork.PolicySelectionResult{
		Allow:      false,
		DenyCode:   "llm_policy.model_blocked",
		DenyReason: `model "claude-opus-4" is not permitted by any applicable policy allowlist`,
	}}
	s := &ProxyServiceServer{}
	s.SetAgentNetworkLimitsService(fake)

	resp, err := s.CheckLLMPolicyLimits(context.Background(), &proto.CheckLLMPolicyLimitsRequest{
		AccountId:  "acc-1",
		ProviderId: "prov-1",
		Model:      "claude-opus-4",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "deny", resp.Decision)
	assert.Equal(t, "llm_policy.model_blocked", resp.DenyCode)
	assert.NotEmpty(t, resp.DenyReason)
	assert.Empty(t, resp.SelectedPolicyId, "a denied request must carry no selected policy")
}

// TestCheckLLMPolicyLimits_SelectorErrorSurfacesAsInternal proves a selector
// failure (e.g. a store error propagated from SelectPolicyForRequest) is
// surfaced as an Internal gRPC error rather than silently allowed.
func TestCheckLLMPolicyLimits_SelectorErrorSurfacesAsInternal(t *testing.T) {
	fake := &fakeAgentNetworkLimits{err: errors.New("boom")}
	s := &ProxyServiceServer{}
	s.SetAgentNetworkLimitsService(fake)

	_, err := s.CheckLLMPolicyLimits(context.Background(), &proto.CheckLLMPolicyLimitsRequest{
		AccountId:  "acc-1",
		ProviderId: "prov-1",
		Model:      "gpt-4o",
	})
	require.Error(t, err)
	st, ok := grpcstatus.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code(), "selector errors must never fail open on the hot path")
}

// TestCheckLLMPolicyLimits_UnconfiguredServiceReturnsUnimplemented locks the
// documented fallback: with no AgentNetworkLimitsService wired, the RPC must
// return Unimplemented rather than panic or silently allow.
func TestCheckLLMPolicyLimits_UnconfiguredServiceReturnsUnimplemented(t *testing.T) {
	s := &ProxyServiceServer{}

	_, err := s.CheckLLMPolicyLimits(context.Background(), &proto.CheckLLMPolicyLimitsRequest{
		AccountId:  "acc-1",
		ProviderId: "prov-1",
	})
	require.Error(t, err)
	st, ok := grpcstatus.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}