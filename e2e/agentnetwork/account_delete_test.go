//go:build e2e

package agentnetwork

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// accountDeleteModel is a made-up model id the provider enumerates and prices,
// so the chat routes to the mock upstream and is metered deterministically.
const accountDeleteModel = "e2e-account-delete-model"

// agentNetworkConfigTables are deleted with the account, in its transaction.
var agentNetworkConfigTables = []string{
	"agent_network_settings",
	"agent_network_providers",
	"agent_network_policies",
	"agent_network_guardrails",
	"agent_network_budget_rules",
}

// TestAccountDelete_RemovesAgentNetworkState deletes an account that has a full
// Agent Network setup and has served traffic, and checks what that leaves
// behind, end to end:
//
//   - the proxy stops running the account's gateway, instead of keeping its
//     mappings and provider API keys in memory until it next resyncs;
//   - the configuration rows go with the account, while access logs and usage
//     records stay for retention;
//   - the account's consumption counters are swept once the cleanup runs;
//   - the gateway domain is free for another account to claim.
//
// It runs on a dedicated server, since deleting the shared account would take
// every other test down with it.
func TestAccountDelete_RemovesAgentNetworkState(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	fresh, err := harnessStartFresh(ctx, t)
	require.NoError(t, err, "start dedicated combined server")

	accounts, err := fresh.API().Accounts.List(ctx)
	require.NoError(t, err, "list accounts")
	require.Len(t, accounts, 1, "a fresh server has exactly the bootstrapped account")
	accountID := accounts[0].Id

	cluster := harness.AgentNetworkCluster
	settings, err := fresh.CreateSettings(ctx, api.AgentNetworkSettingsCreateRequest{ProxyAddress: &cluster})
	require.NoError(t, err, "bootstrap agent-network endpoint")
	require.NotEmpty(t, settings.Endpoint, "endpoint must be assigned at bootstrap")

	env := provisionAccountDeleteEnv(t, ctx, fresh, settings.Endpoint)
	chatThrough(t, ctx, env)

	// Preconditions: the proxy runs the account's gateway, and the request left
	// the traffic-driven rows the rest of the test expects to outlive the delete.
	requireEventually(t, ctx, 60*time.Second, "proxy should run a client for the account", func() bool {
		return proxyRunsAccount(t, ctx, env.proxy, accountID)
	})
	requireEventually(t, ctx, accessLogIngestWindow, "the request should leave consumption, usage and access-log rows", func() bool {
		counts := accountRowCounts(t, fresh, accountID,
			"agent_network_consumption", "agent_network_request_usage", "agent_network_access_log")
		return counts["agent_network_consumption"] > 0 &&
			counts["agent_network_request_usage"] > 0 &&
			counts["agent_network_access_log"] > 0
	})

	require.NoError(t, fresh.API().Accounts.Delete(ctx, accountID), "delete account")

	// The proxy is told to drop the gateway. A proxy that only learns on its
	// next resync keeps serving the deleted account with its provider API keys.
	if !eventually(ctx, 60*time.Second, func() bool { return proxyDroppedAccount(t, ctx, env.proxy, accountID) }) {
		t.Errorf("proxy still runs a client for deleted account %s\n=== proxy logs ===\n%s",
			accountID, env.proxy.Logs(context.Background()))
	}

	counts := accountRowCounts(t, fresh, accountID, append(slices.Clone(agentNetworkConfigTables),
		"agent_network_request_usage", "agent_network_access_log")...)
	for _, table := range agentNetworkConfigTables {
		assert.Zero(t, counts[table], "%s rows should be deleted with the account", table)
	}
	assert.NotZero(t, counts["agent_network_request_usage"], "usage records should be kept")
	assert.NotZero(t, counts["agent_network_access_log"], "access logs should be left for retention")

	// The cleanup's first pass runs at startup, and whether instance setup is
	// open again is only re-evaluated then.
	require.NoError(t, fresh.Restart(ctx), "restart combined server")
	requireEventually(t, ctx, 60*time.Second, "the cleanup should sweep the deleted account's consumption counters", func() bool {
		return accountRowCounts(t, fresh, accountID, "agent_network_consumption")["agent_network_consumption"] == 0
	})

	// A new account can claim the deleted account's gateway domain: its
	// settings row no longer holds the global unique index.
	_, err = fresh.Bootstrap(ctx)
	require.NoError(t, err, "bootstrap a second account once the first is gone")
	claimed, err := fresh.CreateSettings(ctx, api.AgentNetworkSettingsCreateRequest{Endpoint: &settings.Endpoint})
	require.NoError(t, err, "a new account should be able to claim the deleted account's gateway domain")
	assert.Equal(t, settings.Endpoint, claimed.Endpoint, "the new account should hold the released domain")
}

// accountDeleteEnv is a connected gateway for one account: a proxy running the
// debug endpoint, a client peer, and the resolved endpoint.
type accountDeleteEnv struct {
	endpoint string
	proxyIP  string
	client   *harness.Client
	proxy    *harness.Proxy
}

// provisionAccountDeleteEnv gives the server's account one of every Agent
// Network configuration row (provider, guardrail, policy, budget rule; the
// settings row is the caller's) and brings up a proxy and a client. The policy
// and budget rule switch on usage metering, so a request records consumption.
func provisionAccountDeleteEnv(t *testing.T, ctx context.Context, srv *harness.Combined, endpoint string) accountDeleteEnv {
	t.Helper()

	vllm, err := harness.StartVLLM(ctx, srv)
	require.NoError(t, err, "start mock vLLM upstream")
	t.Cleanup(func() { _ = vllm.Terminate(context.Background()) })

	grp, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-account-delete"})
	require.NoError(t, err, "create group")

	ephemeral := false
	sk, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-account-delete-client",
		Type:       "reusable",
		ExpiresIn:  86400,
		AutoGroups: []string{grp.Id},
		Ephemeral:  &ephemeral,
	})
	require.NoError(t, err, "mint setup key")

	apiKey := "sk-account-delete-e2e"
	models := []api.AgentNetworkProviderModel{{Id: accountDeleteModel, InputPer1k: 0.01, OutputPer1k: 0.02}}
	prov, err := srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
		Name:        "account-delete",
		ProviderId:  "openai_api",
		UpstreamUrl: vllm.URL,
		ApiKey:      &apiKey,
		Enabled:     ptr(true),
		Models:      &models,
	})
	require.NoError(t, err, "create provider")

	var gr api.AgentNetworkGuardrailRequest
	gr.Name = "e2e-account-delete"
	gr.Checks.ModelAllowlist.Enabled = true
	gr.Checks.ModelAllowlist.Models = []string{accountDeleteModel}
	guard, err := srv.CreateGuardrail(ctx, gr)
	require.NoError(t, err, "create guardrail")

	limits := api.AgentNetworkPolicyLimits{
		TokenLimit: api.AgentNetworkPolicyTokenLimit{
			Enabled:       true,
			GroupCap:      10_000_000,
			UserCap:       10_000_000,
			WindowSeconds: 60,
		},
	}
	_, err = srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-account-delete",
		Enabled:                ptr(true),
		SourceGroups:           []string{grp.Id},
		DestinationProviderIds: []string{prov.Id},
		GuardrailIds:           &[]string{guard.Id},
		Limits:                 &limits,
	})
	require.NoError(t, err, "create policy")

	_, err = srv.CreateBudgetRule(ctx, api.AgentNetworkBudgetRuleRequest{
		Name:         "e2e-account-delete",
		Limits:       limits,
		TargetGroups: &[]string{grp.Id},
	})
	require.NoError(t, err, "create budget rule")

	proxyToken, err := srv.CreateProxyTokenCLI(ctx, "e2e-account-delete-proxy")
	require.NoError(t, err, "mint proxy token")
	px, err := harness.StartProxy(ctx, srv, proxyToken, map[string]string{"NB_PROXY_DEBUG_ENDPOINT": "true"})
	require.NoError(t, err, "start proxy")
	t.Cleanup(func() { _ = px.Terminate(context.Background()) })

	cl, err := harness.StartClient(ctx, srv, sk.Key)
	require.NoError(t, err, "start client")
	t.Cleanup(func() { _ = cl.Terminate(context.Background()) })

	require.NoError(t, cl.WaitConnected(ctx, 90*time.Second), "client must connect to management")
	proxyIP, err := cl.ResolveProxyIP(ctx, endpoint)
	require.NoError(t, err, "resolve endpoint to proxy IP")
	if err := cl.WaitProxyPeer(ctx, 180*time.Second); err != nil {
		t.Fatalf("client did not see the proxy peer: %v\n=== proxy logs ===\n%s", err, px.Logs(context.Background()))
	}

	return accountDeleteEnv{endpoint: endpoint, proxyIP: proxyIP, client: cl, proxy: px}
}

// chatThrough drives one chat through the gateway, retrying to absorb
// first-call tunnel and DNS jitter.
func chatThrough(t *testing.T, ctx context.Context, env accountDeleteEnv) {
	t.Helper()
	var code int
	var body string
	ok := eventually(ctx, 90*time.Second, func() bool {
		c, b, err := env.client.Chat(ctx, env.endpoint, env.proxyIP, harness.WireChat,
			accountDeleteModel, "Reply with exactly: pong", "e2e-session-account-delete")
		code, body = c, b
		return err == nil && c == 200
	})
	require.True(t, ok, "chat must return 200, last got %d: %s\n=== proxy logs ===\n%s",
		code, body, env.proxy.Logs(context.Background()))
}

// proxyRunsAccount reports whether a lookup succeeded and shows the proxy
// running a client for the account.
func proxyRunsAccount(t *testing.T, ctx context.Context, px *harness.Proxy, accountID string) bool {
	t.Helper()
	runs, ok := lookupProxyAccount(t, ctx, px, accountID)
	return ok && runs
}

// proxyDroppedAccount reports whether a lookup succeeded and shows the proxy
// no longer running a client for the account. A failed lookup confirms
// nothing, so it keeps the caller polling rather than passing the check.
func proxyDroppedAccount(t *testing.T, ctx context.Context, px *harness.Proxy, accountID string) bool {
	t.Helper()
	runs, ok := lookupProxyAccount(t, ctx, px, accountID)
	return ok && !runs
}

// lookupProxyAccount asks the proxy whether it runs a client for the account;
// ok is false when the lookup itself failed.
func lookupProxyAccount(t *testing.T, ctx context.Context, px *harness.Proxy, accountID string) (runs, ok bool) {
	t.Helper()
	clients, err := px.DebugClients(ctx)
	if err != nil {
		t.Logf("proxy debug clients: %v", err)
		return false, false
	}
	return slices.ContainsFunc(clients, func(c harness.ProxyDebugClient) bool { return c.AccountID == accountID }), true
}

// accountRowCounts counts the account's rows in each table, read from a
// snapshot of the management store.
func accountRowCounts(t *testing.T, srv *harness.Combined, accountID string, tables ...string) map[string]int64 {
	t.Helper()
	dbPath, err := srv.SnapshotStoreDB(t.TempDir())
	require.NoError(t, err, "snapshot management sqlite store")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	require.NoError(t, err, "open store snapshot")
	sqlDB, err := db.DB()
	require.NoError(t, err)
	defer func() { _ = sqlDB.Close() }()

	counts := make(map[string]int64, len(tables))
	for _, table := range tables {
		var n int64
		require.NoError(t, db.Table(table).Where("account_id = ?", accountID).Count(&n).Error, "count %s rows", table)
		counts[table] = n
	}
	return counts
}

// eventually polls cond every two seconds until it holds or timeout passes.
func eventually(ctx context.Context, timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) || !waitBeforeRetry(ctx, 2*time.Second) {
			return false
		}
	}
}

// requireEventually fails the test now if cond does not hold within timeout.
func requireEventually(t *testing.T, ctx context.Context, timeout time.Duration, msg string, cond func() bool) {
	t.Helper()
	require.True(t, eventually(ctx, timeout, cond), msg)
}
