//go:build e2e

package agentnetwork

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// TestChatCompletionThroughProxy is Pillar 3: it provisions an agent-network
// gateway (provider + policy + setup key), runs the proxy and a client
// container on the shared network, and drives a real chat-completion from the
// client through the proxy to the upstream provider over the WireGuard tunnel,
// asserting a 200 and that usage is recorded.
//
// Requires a real provider key in OPENAI_TOKEN (source ~/.llm-keys locally; set
// the Actions secret in CI). Skips otherwise.
func TestChatCompletionThroughProxy(t *testing.T) {
	apiKey := os.Getenv("OPENAI_TOKEN")
	if apiKey == "" {
		t.Skip("OPENAI_TOKEN not set; source ~/.llm-keys to run the live chat test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	// Group + setup key: the client joins into this group; the policy authorizes
	// it to reach the provider.
	grp, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-agents"})
	require.NoError(t, err, "create agents group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grp.Id) })

	ephemeral := false
	sk, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-client",
		Type:       "reusable",
		ExpiresIn:  86400,
		UsageLimit: 0,
		AutoGroups: []string{grp.Id},
		Ephemeral:  &ephemeral,
	})
	require.NoError(t, err, "mint setup key")
	require.NotEmpty(t, sk.Key, "setup key must be returned in plaintext")

	// Provider (real upstream key) + policy authorizing the group. Created
	// before the proxy starts so the proxy's initial cluster snapshot already
	// carries the account's synthesized service.
	prov, err := srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
		Name:             "OpenAI Live",
		ProviderId:       "openai_api",
		UpstreamUrl:      "https://api.openai.com",
		ApiKey:           &apiKey,
		Enabled:          ptr(true),
		BootstrapCluster: ptr(harness.AgentNetworkCluster),
		Models: &[]api.AgentNetworkProviderModel{
			{Id: "gpt-4o-mini", InputPer1k: 0.00015, OutputPer1k: 0.0006},
		},
	})
	require.NoError(t, err, "create provider")
	t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), prov.Id) })

	enabled := true
	policyReq := api.AgentNetworkPolicyRequest{
		Name:                   "e2e-allow",
		Enabled:                &enabled,
		SourceGroups:           []string{grp.Id},
		DestinationProviderIds: []string{prov.Id},
	}
	pol, err := srv.CreatePolicy(ctx, policyReq)
	require.NoError(t, err, "create policy")
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), pol.Id) })

	settings, err := srv.GetSettings(ctx)
	require.NoError(t, err, "read settings for endpoint")
	require.NotEmpty(t, settings.Endpoint, "agent-network endpoint must be assigned")

	// Mint the proxy token via the server CLI (global, account-less) — the path
	// the manual install uses, which drives the cluster-snapshot synthesis the
	// proxy needs. An account-scoped REST token takes a different path that
	// doesn't deliver the service.
	proxyToken, err := srv.CreateProxyTokenCLI(ctx, "e2e-proxy")
	require.NoError(t, err, "mint proxy token via CLI")

	px, err := harness.StartProxy(ctx, srv, proxyToken)
	require.NoError(t, err, "start proxy")
	t.Cleanup(func() { _ = px.Terminate(context.Background()) })

	// Client joins last, once the proxy + provider + policy are all in place, so
	// its initial network map includes the synthesized agent-network service.
	cl, err := harness.StartClient(ctx, srv, sk.Key)
	require.NoError(t, err, "start client")
	t.Cleanup(func() { _ = cl.Terminate(context.Background()) })

	require.NoError(t, cl.WaitConnected(ctx, 90*time.Second), "client must connect to management")

	if err := cl.WaitProxyPeer(ctx, 180*time.Second); err != nil {
		dctx := context.Background()
		peers, _ := srv.API().Peers.List(dctx)
		var peerInfo []string
		for _, p := range peers {
			var groups []string
			for _, g := range p.Groups {
				groups = append(groups, g.Name)
			}
			peerInfo = append(peerInfo, fmt.Sprintf("%s connected=%t ip=%s groups=%v", p.Name, p.Connected, p.Ip, groups))
		}
		clusters, _ := srv.API().ReverseProxyClusters.List(dctx)
		var clusterInfo []string
		for _, cl := range clusters {
			clusterInfo = append(clusterInfo, fmt.Sprintf("%+v", cl))
		}
		domains, _ := srv.API().ReverseProxyDomains.List(dctx)
		var domainInfo []string
		for _, d := range domains {
			domainInfo = append(domainInfo, fmt.Sprintf("%+v", d))
		}
		_ = os.WriteFile("/tmp/nb-e2e-proxy.log", []byte(px.Logs(dctx)), 0o644)
		_ = os.WriteFile("/tmp/nb-e2e-client.log", []byte(cl.Logs(dctx)), 0o644)
		_ = os.WriteFile("/tmp/nb-e2e-combined.log", []byte(srv.Logs(dctx)), 0o644)
		diag := fmt.Sprintf("settings: cluster=%q endpoint=%q subdomain=%q\nprovider: id=%s cluster=%s\npolicy: id=%s sourceGroups=%v dst=%v\ngroup: id=%s\npeers:\n%s\nclusters:\n%s\n",
			settings.Cluster, settings.Endpoint, settings.Subdomain,
			prov.Id, harness.AgentNetworkCluster,
			pol.Id, policyReq.SourceGroups, policyReq.DestinationProviderIds,
			grp.Id,
			strings.Join(peerInfo, "\n"), strings.Join(clusterInfo, "\n"))
		diag += "domains:\n" + strings.Join(domainInfo, "\n") + "\n"
		_ = os.WriteFile("/tmp/nb-e2e-diag.txt", []byte(diag), 0o644)
		t.Fatalf("client did not see the proxy peer: %v\n=== settings ===\ncluster=%q endpoint=%q subdomain=%q\n=== peers ===\n%v\n=== clusters ===\n%v\n=== proxy logs ===\n%s",
			err, settings.Cluster, settings.Endpoint, settings.Subdomain, peerInfo, clusterInfo, px.Logs(dctx))
	}

	proxyIP, err := cl.ResolveProxyIP(ctx, settings.Endpoint)
	require.NoError(t, err, "resolve agent-network endpoint to proxy IP")

	code, body, err := cl.Chat(ctx, settings.Endpoint, proxyIP, "gpt-4o-mini", "Reply with exactly: pong")
	require.NoError(t, err, "chat request through tunnel")
	if code != 200 {
		t.Fatalf("expected 200 from chat-completion, got %d\nbody: %s\n=== proxy logs ===\n%s", code, body, px.Logs(context.Background()))
	}
	assert.Contains(t, body, "choices", "chat response should carry choices")

	// The per-request access-log row is ingested asynchronously after the
	// response is forwarded; poll briefly. (Consumption rows are only booked
	// when a policy has token/budget limits, which this one doesn't.)
	require.Eventually(t, func() bool {
		resp, lerr := srv.ListAccessLogs(ctx)
		return lerr == nil && resp.TotalRecords > 0
	}, 30*time.Second, 2*time.Second, "an access-log row should be recorded after the chat-completion")

	logs, err := srv.ListAccessLogs(ctx)
	require.NoError(t, err, "read access logs")
	require.NotEmpty(t, logs.Data, "access-log page must contain the request row")
	require.NotNil(t, logs.Data[0].Model, "access-log row should record the model")
	assert.Equal(t, "gpt-4o-mini", *logs.Data[0].Model, "access-log row should record the requested model")
}
