//go:build e2e

package agentnetwork

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// TestModelAllowlistOfDeclaredIDsServed drives the setup an operator actually
// builds for a path-routed provider: the models are declared in the form the
// vendor issues (Bedrock's region-prefixed, versioned inference-profile id;
// Vertex's model@version), and the guardrail allowlist is built from that
// declared list — the dashboard's allowlist picker persists the declared ids
// verbatim. A request for the declared model must be served end to end, and a
// model outside the allowlist must still be denied.
//
// TestModelAllowlistEnforced never caught this because it registers and
// allowlists the pre-normalized catalog form (see the catalogModel comment
// there and the one in providerRequest: "register the normalized form here or
// routing fails as model_not_routable") — the harness encoded the
// canonicalization workaround instead of the shape operators configure.
func TestModelAllowlistOfDeclaredIDsServed(t *testing.T) {
	var providers []providerCase
	for _, pc := range availableProviders() {
		if pc.kind == harness.WireBedrock || pc.kind == harness.WireVertex {
			providers = append(providers, pc)
		}
	}
	if len(providers) == 0 {
		t.Skip("no path-routed provider keys set (AWS_BEARER_TOKEN_BEDROCK / GOOGLE_VERTEX_*); source ~/.llm-keys")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	grp, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-declared-allowlist"})
	require.NoError(t, err, "create group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grp.Id) })

	ephemeral := false
	sk, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-declared-allowlist-client",
		Type:       "reusable",
		ExpiresIn:  86400,
		UsageLimit: 0,
		AutoGroups: []string{grp.Id},
		Ephemeral:  &ephemeral,
	})
	require.NoError(t, err, "mint setup key")
	t.Cleanup(func() { _ = srv.API().SetupKeys.Delete(context.Background(), sk.Id) })

	// Providers declaring the raw vendor-issued model id — NOT the normalized
	// catalog form providerRequest would register.
	ids := make([]string, 0, len(providers))
	declared := make([]string, 0, len(providers))
	for _, pc := range providers {
		req := providerRequest(pc)
		req.Models = &[]api.AgentNetworkProviderModel{{Id: pc.model, InputPer1k: 0.001, OutputPer1k: 0.002}}
		prov, perr := srv.CreateProvider(ctx, req)
		require.NoError(t, perr, "create provider %s", pc.name)
		id := prov.Id
		ids = append(ids, id)
		declared = append(declared, pc.model)
		t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), id) })
	}

	// Guardrail allowlisting the declared ids verbatim, the way the dashboard
	// builds an allowlist from the providers' model lists.
	var gr api.AgentNetworkGuardrailRequest
	gr.Name = "e2e-declared-allowlist"
	gr.Checks.ModelAllowlist.Enabled = true
	gr.Checks.ModelAllowlist.Models = declared
	guard, err := srv.CreateGuardrail(ctx, gr)
	require.NoError(t, err, "create guardrail")
	t.Cleanup(func() { _ = srv.DeleteGuardrail(context.Background(), guard.Id) })

	enabled := true
	pol, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-declared-allowlist",
		Enabled:                &enabled,
		SourceGroups:           []string{grp.Id},
		DestinationProviderIds: ids,
		GuardrailIds:           &[]string{guard.Id},
	})
	require.NoError(t, err, "create policy")
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), pol.Id) })

	settings, err := srv.GetSettings(ctx)
	require.NoError(t, err, "read settings for endpoint")
	require.NotEmpty(t, settings.Endpoint, "agent-network endpoint must be assigned")

	proxyToken, err := srv.CreateProxyTokenCLI(ctx, "e2e-proxy-declared-allowlist")
	require.NoError(t, err, "mint proxy token via CLI")
	px, err := harness.StartProxy(ctx, srv, proxyToken)
	require.NoError(t, err, "start proxy")
	t.Cleanup(func() { _ = px.Terminate(context.Background()) })

	cl, err := harness.StartClient(ctx, srv, sk.Key)
	require.NoError(t, err, "start client")
	t.Cleanup(func() { _ = cl.Terminate(context.Background()) })

	require.NoError(t, cl.WaitConnected(ctx, 90*time.Second), "client must connect to management")
	// Probe first: the GET resolves the endpoint (DNS error fails) and its first packet wakes the lazy proxy peer, so WaitProxyPeer sees it connected; any HTTP status counts.
	proxyIP, err := cl.ResolveProxyIP(ctx, settings.Endpoint)
	require.NoError(t, err, "resolve agent-network endpoint to proxy IP")
	if err := cl.WaitProxyPeer(ctx, 180*time.Second); err != nil {
		t.Fatalf("client did not see the proxy peer: %v\n=== proxy logs ===\n%s", err, px.Logs(context.Background()))
	}

	for _, pc := range providers {
		pc := pc
		t.Run(pc.name, func(t *testing.T) {
			// The model the operator declared and allowlisted is served end to
			// end: the route must claim it and the guardrail must permit it,
			// both through the canonicalization the parser applies at request
			// time — whatever id form the operator configured.
			assert.Equal(t, 200, sendModel(ctx, t, cl, settings.Endpoint, proxyIP, pc, pc.model),
				"the declared and allowlisted model must be served for %s", pc.name)
			// A model outside the allowlist stays denied.
			assert.Equal(t, 403, sendModel(ctx, t, cl, settings.Endpoint, proxyIP, pc, disallowedModel(pc)),
				"model outside the allowlist must be denied for %s", pc.name)
		})
	}
}
