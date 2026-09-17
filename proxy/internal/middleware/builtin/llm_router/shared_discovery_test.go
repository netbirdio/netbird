package llm_router

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
)

func TestRouter_ListingCombinesSharedGatewayRecords(t *testing.T) {
	base := ProviderRoute{
		ID: "first", Models: []string{"model-a"},
		UpstreamScheme: "https", UpstreamHost: "gateway.example.com",
		AuthHeaderName: "Authorization", AuthHeaderValue: "Bearer test-key",
		AllowedGroupIDs: []string{defaultTestGroup},
	}
	second := base
	second.ID = "second"
	second.Models = []string{"model-b", "model-a", "restricted"}
	second.ModelPolicies = []ModelPolicyRule{
		{GroupIDs: []string{defaultTestGroup}, Models: []string{"model-b", "model-a"}},
		{GroupIDs: []string{"other-team"}, Models: []string{"restricted"}},
	}
	third := base
	third.ID = "third"
	third.Models = []string{"model-c"}
	mw := New(Config{Providers: []ProviderRoute{base, second, third}})
	out, err := mw.Invoke(context.Background(), newModellessInput(modelListingPath))
	require.NoError(t, err)
	require.Equal(t, middleware.DecisionAllow, out.Decision, "authorized listing should pass")
	require.NotNil(t, out.Mutations)
	require.NotNil(t, out.Mutations.RewriteUpstream)
	assert.Equal(t, []string{"model-a", "model-b", "model-c"}, out.Mutations.RewriteUpstream.DiscoveryModels,
		"the gateway listing must retain each authorized record's models exactly once")
	assert.Equal(t, "gateway.example.com", out.Mutations.RewriteUpstream.Host, "listing upstream must stay unchanged")
	provider, _ := metaValue(t, out.Metadata, middleware.KeyLLMResolvedProviderID)
	assert.Equal(t, base.ID, provider, "the selected upstream record must stay unchanged")
	assert.Equal(t, []string{"model-a"}, base.Models, "listing must not mutate configured model slices")
}

func TestRouter_ListingKeepsOtherUpstreamsSeparate(t *testing.T) {
	base := ProviderRoute{
		ID: "first", Models: []string{"model-a"},
		UpstreamScheme: "https", UpstreamHost: "gateway.example.com",
		AuthHeaderName: "Authorization", AuthHeaderValue: "Bearer test-key",
		AllowedGroupIDs: []string{defaultTestGroup},
	}
	tests := []struct {
		name   string
		change func(*ProviderRoute)
	}{
		{"unauthorized group", func(p *ProviderRoute) { p.AllowedGroupIDs = []string{"other-team"} }},
		{"no authorized groups", func(p *ProviderRoute) { p.AllowedGroupIDs = nil }},
		{"unauthorized catch-all", func(p *ProviderRoute) { p.AllowedGroupIDs = []string{"other-team"}; p.Models = nil }},
		{"policy denies all models", func(p *ProviderRoute) {
			p.ModelPolicies = []ModelPolicyRule{{GroupIDs: []string{defaultTestGroup}, Models: []string{}}}
		}},
		{"different host", func(p *ProviderRoute) { p.UpstreamHost = "other.example.com" }},
		{"different scheme", func(p *ProviderRoute) { p.UpstreamScheme = "http" }},
		{"different path", func(p *ProviderRoute) { p.UpstreamPath = "/other" }},
		{"different credential", func(p *ProviderRoute) { p.AuthHeaderValue = "Bearer other-key" }},
		{"different auth header", func(p *ProviderRoute) { p.AuthHeaderName = "X-Api-Key" }},
		{"different discovery host", func(p *ProviderRoute) { p.DiscoveryHost = "discovery.example.com" }},
		{"different TLS verification", func(p *ProviderRoute) { p.SkipTLSVerify = true }},
		{"service account credential", func(p *ProviderRoute) { p.GCPServiceAccountKeyB64 = "other-credential" }},
		{"vertex", func(p *ProviderRoute) { p.Vertex = true }},
		{"bedrock", func(p *ProviderRoute) { p.Bedrock = true }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			other := base
			other.ID = "other"
			other.Models = []string{"model-b"}
			tt.change(&other)
			mw := New(Config{Providers: []ProviderRoute{base, other}})
			out, err := mw.Invoke(context.Background(), newModellessInput(modelListingPath))
			require.NoError(t, err)
			require.NotNil(t, out.Mutations)
			require.NotNil(t, out.Mutations.RewriteUpstream)
			assert.Equal(t, []string{"model-a"}, out.Mutations.RewriteUpstream.DiscoveryModels,
				"a different or unauthorized upstream must not contribute models")
		})
	}
}

func TestRouter_SharedGatewayCatchAllListing(t *testing.T) {
	first := ProviderRoute{ID: "first", Models: []string{"model-a"},
		UpstreamScheme: "https", UpstreamHost: "gateway.example.com",
		AllowedGroupIDs: []string{defaultTestGroup}}
	catchAll := first
	catchAll.ID = "catch-all"
	catchAll.Models = nil
	for _, restricted := range []bool{false, true} {
		t.Run(map[bool]string{false: "unrestricted", true: "policy restricted"}[restricted], func(t *testing.T) {
			route := catchAll
			if restricted {
				route.ModelPolicies = []ModelPolicyRule{{GroupIDs: []string{defaultTestGroup}, Models: []string{"model-b"}}}
			}
			mw := New(Config{Providers: []ProviderRoute{first, route}})
			out, err := mw.Invoke(context.Background(), newModellessInput(modelListingPath))
			require.NoError(t, err)
			require.NotNil(t, out.Mutations.RewriteUpstream)
			if restricted {
				assert.Equal(t, []string{"model-a", "model-b"}, out.Mutations.RewriteUpstream.DiscoveryModels,
					"a catch-all's policy must still bound its contribution")
			} else {
				assert.Nil(t, out.Mutations.RewriteUpstream.DiscoveryModels,
					"an authorized unrestricted record exposes the shared gateway's full listing")
			}
		})
	}
}
