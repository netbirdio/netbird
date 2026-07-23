//go:build e2e

package agentnetwork

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// bedrockRegionPrefixes and bedrockVersionSuffix mirror the proxy's Bedrock
// model normalization (region/inference-profile prefix + version suffix) so the
// provider is registered under the same catalog key the router matches against.
var (
	bedrockRegionPrefixes = []string{"us.", "eu.", "apac.", "global."}
	bedrockVersionSuffix  = regexp.MustCompile(`-(\d{8}-)?v\d+(:\d+)?$`)
)

// catalogModel returns the normalized catalog id the proxy stamps for a
// path-routed provider's configured model — the form the router and guardrail
// allowlist compare against (Bedrock region prefix + version stripped, Vertex
// @version stripped).
func catalogModel(pc providerCase) string {
	switch pc.kind {
	case harness.WireBedrock:
		m := pc.model
		for _, p := range bedrockRegionPrefixes {
			if strings.HasPrefix(m, p) {
				m = m[len(p):]
				break
			}
		}
		return bedrockVersionSuffix.ReplaceAllString(m, "")
	case harness.WireVertex:
		return strings.SplitN(pc.model, "@", 2)[0]
	default:
		return pc.model
	}
}

// disallowedModel returns a valid-shaped model id for the provider that is NOT
// the configured/allowed one, so the guardrail must reject it before the
// request ever reaches the upstream.
func disallowedModel(pc providerCase) string {
	switch pc.kind {
	case harness.WireBedrock:
		// Same profile prefix as the allowed model so only the model name
		// differs; the guardrail must deny it before it reaches AWS.
		return strings.SplitN(pc.model, ".", 2)[0] + ".anthropic.claude-opus-4-8"
	case harness.WireVertex:
		return "claude-opus-4-8@20250101"
	default:
		return "unlisted-model"
	}
}

// sendModel drives one request for the given model through the provider's native
// wire shape and returns the HTTP status.
func sendModel(ctx context.Context, t *testing.T, cl *harness.Client, endpoint, proxyIP string, pc providerCase, model string) int {
	t.Helper()
	var code int
	var err error
	switch pc.kind {
	case harness.WireBedrock:
		code, _, err = cl.Bedrock(ctx, endpoint, proxyIP, model, "Reply with exactly: pong", "")
	case harness.WireVertex:
		code, _, err = cl.Vertex(ctx, endpoint, proxyIP, pc.project, pc.region, model, "Reply with exactly: pong", "")
	default:
		code, _, err = cl.ChatPrefixed(ctx, endpoint, proxyIP, pc.pathPrefix, pc.kind, model, "Reply with exactly: pong", "")
	}
	require.NoError(t, err, "request must reach the proxy for %s", pc.name)
	return code
}

// TestModelAllowlistEnforced provisions a Model Allowlist guardrail limiting each
// path-routed provider (Bedrock, Vertex) to its configured model, then drives
// requests over the tunnel: the allowed model returns 200 while a model outside
// the allowlist is denied 403 by the guardrail before it reaches the upstream.
// This is the coverage missing for #6751 — the model for these providers travels
// in the URL path, and the allowlist must be enforced there.
func TestModelAllowlistEnforced(t *testing.T) {
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

	grp, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-allowlist"})
	require.NoError(t, err, "create group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grp.Id) })

	ephemeral := false
	sk, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-allowlist-client",
		Type:       "reusable",
		ExpiresIn:  86400,
		UsageLimit: 0,
		AutoGroups: []string{grp.Id},
		Ephemeral:  &ephemeral,
	})
	require.NoError(t, err, "mint setup key")

	// Providers with their configured (allowed) models; the first bootstraps the cluster.
	ids := make([]string, 0, len(providers))
	allowed := make([]string, 0, len(providers))
	for i, pc := range providers {
		req := providerRequest(pc)
		if i == 0 {
			req.BootstrapCluster = ptr(harness.AgentNetworkCluster)
		}
		prov, perr := srv.CreateProvider(ctx, req)
		require.NoError(t, perr, "create provider %s", pc.name)
		id := prov.Id
		ids = append(ids, id)
		allowed = append(allowed, catalogModel(pc))
		t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), id) })
	}

	// Guardrail allowlisting exactly the configured models.
	var gr api.AgentNetworkGuardrailRequest
	gr.Name = "e2e-allowlist"
	gr.Checks.ModelAllowlist.Enabled = true
	gr.Checks.ModelAllowlist.Models = allowed
	guard, err := srv.CreateGuardrail(ctx, gr)
	require.NoError(t, err, "create guardrail")
	t.Cleanup(func() { _ = srv.DeleteGuardrail(context.Background(), guard.Id) })

	enabled := true
	pol, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-allowlist",
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

	proxyToken, err := srv.CreateProxyTokenCLI(ctx, "e2e-proxy-allowlist")
	require.NoError(t, err, "mint proxy token via CLI")
	px, err := harness.StartProxy(ctx, srv, proxyToken)
	require.NoError(t, err, "start proxy")
	t.Cleanup(func() { _ = px.Terminate(context.Background()) })

	cl, err := harness.StartClient(ctx, srv, sk.Key)
	require.NoError(t, err, "start client")
	t.Cleanup(func() { _ = cl.Terminate(context.Background()) })

	require.NoError(t, cl.WaitConnected(ctx, 90*time.Second), "client must connect to management")
	// Resolve first: the DNS lookup triggers the lazy-connection warm-up, waking
	// the proxy peer so WaitProxyPeer then observes it connected.
	proxyIP, err := cl.ResolveProxyIP(ctx, settings.Endpoint)
	require.NoError(t, err, "resolve agent-network endpoint to proxy IP")
	if err := cl.WaitProxyPeer(ctx, 180*time.Second); err != nil {
		t.Fatalf("client did not see the proxy peer: %v\n=== proxy logs ===\n%s", err, px.Logs(context.Background()))
	}

	for _, pc := range providers {
		pc := pc
		t.Run(pc.name, func(t *testing.T) {
			// The admin's allowlisted model is served end to end.
			assert.Equal(t, 200, sendModel(ctx, t, cl, settings.Endpoint, proxyIP, pc, pc.model),
				"allowlisted model must be permitted for %s", pc.name)
			// A model outside the allowlist is rejected by the guardrail (before
			// the upstream), regardless of whether it is a real catalog model.
			assert.Equal(t, 403, sendModel(ctx, t, cl, settings.Endpoint, proxyIP, pc, disallowedModel(pc)),
				"model outside the allowlist must be denied for %s", pc.name)
		})
	}
}
