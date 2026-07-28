//go:build e2e

package agentnetwork

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/client/rest"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

func ptr[T any](v T) *T { return &v }

// newProvider creates an OpenAI-catalog provider with a dummy key (these tests
// never call the upstream) and registers cleanup.
func newProvider(t *testing.T, ctx context.Context, name string) api.AgentNetworkProvider {
	t.Helper()
	prov, err := srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
		Name:             name,
		ProviderId:       "openai_api",
		UpstreamUrl:      "https://api.openai.com",
		ApiKey:           ptr("sk-dummy-e2e-key"),
		BootstrapCluster: ptr("eu.proxy.netbird.test"),
	})
	require.NoError(t, err, "create provider %q", name)
	t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), prov.Id) })
	return prov
}

// requireClientError asserts err is a REST APIError with a 4xx status.
func requireClientError(t *testing.T, err error) {
	t.Helper()
	var apiErr *rest.APIError
	require.ErrorAs(t, err, &apiErr, "expected a REST APIError")
	assert.GreaterOrEqual(t, apiErr.StatusCode, 400, "expected a 4xx status")
	assert.Less(t, apiErr.StatusCode, 500, "expected a 4xx status")
}

// TestProviderLifecycle covers create → get → list → delete → 404 for every
// available real provider catalog (and a synthetic OpenAI provider when no
// provider keys are set), so each catalog's create and field round-trip is
// exercised. Create is offline — no upstream call — so this stays fast and
// burns no provider quota.
func TestProviderLifecycle(t *testing.T) {
	ctx := context.Background()

	cases := availableProviders()
	if len(cases) == 0 {
		cases = []providerCase{{
			name: "openai", catalogID: "openai_api", upstream: "https://api.openai.com",
			apiKey: "sk-dummy-e2e-key", model: "gpt-4o-mini", kind: harness.WireChat,
		}}
	}

	for i, pc := range cases {
		i, pc := i, pc
		t.Run(pc.name, func(t *testing.T) {
			req := providerRequest(pc)
			req.Name = "lc-" + pc.name
			// Bootstrap the cluster on the first create in case the matrix has
			// not run (e.g. no provider keys → settings not yet bootstrapped).
			if i == 0 {
				req.BootstrapCluster = ptr(harness.AgentNetworkCluster)
			}

			prov, err := srv.CreateProvider(ctx, req)
			require.NoError(t, err, "create %s provider", pc.name)
			t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), prov.Id) })

			assert.NotEmpty(t, prov.Id, "created provider must have an id")
			assert.Equal(t, pc.catalogID, prov.ProviderId, "catalog id must round-trip")
			assert.Equal(t, req.Name, prov.Name, "name must round-trip")
			assert.Equal(t, pc.upstream, prov.UpstreamUrl, "upstream must round-trip")

			got, err := srv.GetProvider(ctx, prov.Id)
			require.NoError(t, err, "get provider")
			assert.Equal(t, prov.Id, got.Id)

			list, err := srv.ListProviders(ctx)
			require.NoError(t, err, "list providers")
			var ids []string
			for _, p := range list {
				ids = append(ids, p.Id)
			}
			assert.Contains(t, ids, prov.Id, "created provider must appear in the list")

			require.NoError(t, srv.DeleteProvider(ctx, prov.Id), "delete provider")
			_, err = srv.GetProvider(ctx, prov.Id)
			requireClientError(t, err)
		})
	}
}

// TestProviderValidation exercises the create-time validation rules. These are
// uniform across catalogs (no per-provider required-field rules exist: a
// catalog-specific malformed value such as a Vertex key without the keyfile::
// prefix is accepted at create and only fails at the proxy), so the cases here
// are catalog-agnostic: missing API key, unknown catalog id, an invalid upstream
// URL, and a blank name.
func TestProviderValidation(t *testing.T) {
	ctx := context.Background()

	_, err := srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
		Name:        "No Key",
		ProviderId:  "openai_api",
		UpstreamUrl: "https://api.openai.com",
	})
	requireClientError(t, err)

	_, err = srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
		Name:        "Unknown Catalog",
		ProviderId:  "totally_unknown_provider",
		UpstreamUrl: "https://example.com",
		ApiKey:      ptr("sk-dummy"),
	})
	requireClientError(t, err)

	_, err = srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
		Name:        "Bad Upstream",
		ProviderId:  "openai_api",
		UpstreamUrl: "not-a-url",
		ApiKey:      ptr("sk-dummy"),
	})
	requireClientError(t, err)

	_, err = srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
		Name:        "   ",
		ProviderId:  "openai_api",
		UpstreamUrl: "https://api.openai.com",
		ApiKey:      ptr("sk-dummy"),
	})
	requireClientError(t, err)
}

// TestSettingsRoundTrip flips the collection toggles and confirms cluster /
// subdomain stay immutable, then restores the original state.
func TestSettingsRoundTrip(t *testing.T) {
	ctx := context.Background()

	// Settings are bootstrapped on first provider create.
	newProvider(t, ctx, "Settings Bootstrap")

	before, err := srv.GetSettings(ctx)
	require.NoError(t, err, "get settings")
	require.NotEmpty(t, before.Cluster, "settings must carry an assigned cluster")

	flipped, err := srv.UpdateSettings(ctx, api.AgentNetworkSettingsRequest{
		EnableLogCollection:    !before.EnableLogCollection,
		EnablePromptCollection: !before.EnablePromptCollection,
		RedactPii:              !before.RedactPii,
	})
	require.NoError(t, err, "update settings")
	assert.Equal(t, !before.EnableLogCollection, flipped.EnableLogCollection, "log collection toggle must flip")
	assert.Equal(t, !before.EnablePromptCollection, flipped.EnablePromptCollection, "prompt collection toggle must flip")
	assert.Equal(t, before.Cluster, flipped.Cluster, "cluster must be immutable across updates")
	assert.Equal(t, before.Subdomain, flipped.Subdomain, "subdomain must be immutable across updates")

	// Restore the original toggles.
	_, err = srv.UpdateSettings(ctx, api.AgentNetworkSettingsRequest{
		EnableLogCollection:    before.EnableLogCollection,
		EnablePromptCollection: before.EnablePromptCollection,
		RedactPii:              before.RedactPii,
	})
	require.NoError(t, err, "restore settings")
}

// TestPolicyWindowFloor rejects an enabled limit below the 60s window floor and
// accepts one at the floor.
func TestPolicyWindowFloor(t *testing.T) {
	ctx := context.Background()

	grp, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-policy-grp"})
	require.NoError(t, err, "create source group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grp.Id) })

	prov := newProvider(t, ctx, "Policy Provider")

	limits := func(window int64) *api.AgentNetworkPolicyLimits {
		return &api.AgentNetworkPolicyLimits{
			TokenLimit: api.AgentNetworkPolicyTokenLimit{
				Enabled:       true,
				GroupCap:      1000,
				UserCap:       1000,
				WindowSeconds: window,
			},
		}
	}

	_, err = srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-below-floor",
		SourceGroups:           []string{grp.Id},
		DestinationProviderIds: []string{prov.Id},
		Limits:                 limits(30),
	})
	requireClientError(t, err)

	pol, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-at-floor",
		SourceGroups:           []string{grp.Id},
		DestinationProviderIds: []string{prov.Id},
		Limits:                 limits(60),
	})
	require.NoError(t, err, "policy at the 60s floor must be accepted")
	assert.NotEmpty(t, pol.Id, "created policy must have an id")
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), pol.Id) })
}

// TestConsumptionList confirms the read endpoint always returns an array, never
// a 404/500.
func TestConsumptionList(t *testing.T) {
	ctx := context.Background()

	rows, err := srv.ListConsumption(ctx)
	require.NoError(t, err, "consumption list must not error")
	assert.NotNil(t, rows, "consumption must be a JSON array (possibly empty)")
}
