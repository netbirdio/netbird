//go:build e2e

package agentnetwork

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

func TestAgentNetworkPlayground(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	vllm, err := harness.StartVLLM(ctx, srv)
	require.NoError(t, err, "start mock vLLM server")
	t.Cleanup(func() { _ = vllm.Terminate(context.Background()) })

	allowedGroup, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "playground-allowed"})
	require.NoError(t, err, "create allowed group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), allowedGroup.Id) })
	deniedGroup, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "playground-denied"})
	require.NoError(t, err, "create denied group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), deniedGroup.Id) })

	ephemeral := false
	setupKey, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "playground-client",
		Type:       "reusable",
		ExpiresIn:  86400,
		UsageLimit: 0,
		AutoGroups: []string{allowedGroup.Id},
		Ephemeral:  &ephemeral,
	})
	require.NoError(t, err, "create client setup key")

	dummyKey := "sk-playground-e2e"
	provider, err := srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
		Name:        "playground-vllm",
		ProviderId:  "vllm",
		UpstreamUrl: vllm.URL,
		ApiKey:      &dummyKey,
		Enabled:     ptr(true),
		Models: &[]api.AgentNetworkProviderModel{
			{Id: harness.VLLMModel, InputPer1k: 0.001, OutputPer1k: 0.002},
		},
	})
	require.NoError(t, err, "create playground provider")
	t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), provider.Id) })

	enabled := true
	policy, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "playground-allow",
		Enabled:                &enabled,
		SourceGroups:           []string{allowedGroup.Id},
		DestinationProviderIds: []string{provider.Id},
		Limits: &api.AgentNetworkPolicyLimits{
			TokenLimit: api.AgentNetworkPolicyTokenLimit{
				Enabled:       true,
				GroupCap:      10_000_000,
				UserCap:       10_000_000,
				WindowSeconds: 60,
			},
		},
	})
	require.NoError(t, err, "create playground policy")
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), policy.Id) })

	proxyToken, err := srv.CreateProxyTokenCLI(ctx, "e2e-playground-proxy")
	require.NoError(t, err, "mint proxy token")
	playgroundProxy, err := harness.StartProxy(ctx, srv, proxyToken)
	require.NoError(t, err, "start playground proxy")
	t.Cleanup(func() { _ = playgroundProxy.Terminate(context.Background()) })

	client, err := harness.StartClient(ctx, srv, setupKey.Key)
	require.NoError(t, err, "start identity client")
	t.Cleanup(func() { _ = client.Terminate(context.Background()) })
	require.NoError(t, client.WaitConnected(ctx, 90*time.Second), "identity client must connect")

	peer := playgroundClientPeer(t, ctx, allowedGroup.Id)
	expectedUserID := peer.UserId
	if expectedUserID == "" {
		expectedUserID = peer.Id
	}

	sessionID := "e2e-session-playground"
	requestBody, err := json.Marshal(map[string]any{
		"model": harness.VLLMModel,
		"messages": []map[string]string{
			{"role": "user", "content": "Reply with exactly: pong"},
		},
		"stream": false,
	})
	require.NoError(t, err)
	request := api.AgentNetworkPlaygroundRequest{
		Principal: api.AgentNetworkPlaygroundPrincipal{
			Kind: api.AgentNetworkPlaygroundPrincipalKindPeer,
			Id:   peer.Id,
		},
		Method: api.AgentNetworkPlaygroundRequestMethodPOST,
		Path:   "/v1/chat/completions",
		Headers: []api.AgentNetworkPlaygroundHeader{
			{Name: "Content-Type", Values: []string{"application/json"}},
			{Name: "X-Session-ID", Values: []string{sessionID}},
		},
		Body: string(requestBody),
	}

	var allowed api.AgentNetworkPlaygroundResponse
	require.Eventually(t, func() bool {
		response, requestErr := srv.ExecutePlayground(ctx, request)
		if requestErr != nil || response.StatusCode != 200 {
			return false
		}
		allowed = response
		return true
	}, 90*time.Second, 3*time.Second, "peer playground request should reach vLLM")
	assert.Contains(t, allowed.Body, "pong", "Provider body should contain the real completion")
	assert.Equal(t, expectedUserID, allowed.Identity.UserId, "Proxy should resolve the peer principal")
	assert.Contains(t, allowed.Identity.GroupIds, allowedGroup.Id, "Proxy should resolve current peer groups")
	assert.Equal(t, "allow", allowed.Policy.Decision, "Policy summary should reflect the live router")
	assert.Equal(t, provider.Id, allowed.Policy.ResolvedProviderId, "Resolved provider should be authoritative")
	assert.Equal(t, policy.Id, allowed.Policy.SelectedPolicyId, "Selected policy should be returned")
	assert.Equal(t, allowedGroup.Id, allowed.Policy.AttributionGroupId, "Usage should be attributed to the authorising group")

	require.Eventually(t, func() bool {
		logs, logErr := srv.ListAccessLogs(ctx)
		if logErr != nil {
			return false
		}
		for _, entry := range logs.Data {
			if entry.SessionId != nil && *entry.SessionId == sessionID {
				return entry.InputTokens > 0 && entry.OutputTokens > 0
			}
		}
		return false
	}, 30*time.Second, 2*time.Second, "playground request should create a metered access log")

	require.Eventually(t, func() bool {
		rows, consumptionErr := srv.ListConsumption(ctx)
		if consumptionErr != nil {
			return false
		}
		for _, row := range rows {
			if row.DimensionId == allowedGroup.Id && row.TokensInput > 0 && row.TokensOutput > 0 {
				return true
			}
		}
		return false
	}, 60*time.Second, 3*time.Second, "playground usage should update group consumption")
	beforeDenied := playgroundConsumptionTokens(t, ctx)

	request.Principal = api.AgentNetworkPlaygroundPrincipal{
		Kind: api.AgentNetworkPlaygroundPrincipalKindGroup,
		Id:   deniedGroup.Id,
	}
	request.Headers = []api.AgentNetworkPlaygroundHeader{
		{Name: "Content-Type", Values: []string{"application/json"}},
	}
	denied, err := srv.ExecutePlayground(ctx, request)
	require.NoError(t, err, "policy denial should be a nested playground response")
	assert.Equal(t, 403, denied.StatusCode, "Unauthorized synthetic group should be denied")
	assert.Empty(t, denied.Identity.UserId, "Synthetic group should carry no user")
	assert.Equal(t, []string{deniedGroup.Id}, denied.Identity.GroupIds, "Synthetic identity should contain exactly the selected group")
	assert.Equal(t, "deny", denied.Policy.Decision, "Policy summary should report denial")
	assert.Contains(t, denied.Body, "llm_policy.no_authorised_provider", "Provider router deny code should be preserved")

	time.Sleep(2 * time.Second)
	assert.Equal(t, beforeDenied, playgroundConsumptionTokens(t, ctx), "Denied request should not increment usage")
}

func playgroundClientPeer(t *testing.T, ctx context.Context, groupID string) api.Peer {
	t.Helper()
	peers, err := srv.API().Peers.List(ctx)
	require.NoError(t, err, "list peers")
	for _, peer := range peers {
		for _, group := range peer.Groups {
			if group.Id == groupID {
				return peer
			}
		}
	}
	t.Fatalf("no client peer found in group %s", groupID)
	return api.Peer{}
}

func playgroundConsumptionTokens(t *testing.T, ctx context.Context) int64 {
	t.Helper()
	rows, err := srv.ListConsumption(ctx)
	require.NoError(t, err, "list playground consumption")
	var total int64
	for _, row := range rows {
		total += row.TokensInput + row.TokensOutput
	}
	return total
}
