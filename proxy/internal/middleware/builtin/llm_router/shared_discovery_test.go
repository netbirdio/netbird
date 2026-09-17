package llm_router

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
)

// TestRouter_ListingCombinesSharedGatewayRecords protects model pickers when
// equivalent authenticated gateway requests are split across provider records.
func TestRouter_ListingCombinesSharedGatewayRecords(t *testing.T) {
	base := ProviderRoute{
		ID: "first", Models: []string{"model-a"},
		UpstreamScheme: "https", UpstreamHost: "gateway.example.com",
		AuthHeaderName: "Authorization", AuthHeaderValue: "Bearer test-key",
		AllowedGroupIDs: []string{defaultTestGroup},
	}
	second := base
	second.ID = "second"
	second.AuthHeaderName = "authorization"
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

// TestRouter_ListingKeepsOtherUpstreamsSeparate guards the tenant and policy
// boundaries even when another record claims models on the same gateway host.
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
		{"credential case differs", func(p *ProviderRoute) { p.AuthHeaderValue = "Bearer TEST-KEY" }},
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

// TestRouter_SharedGatewayCatchAllListing keeps an unrestricted gateway usable
// without allowing a policy-restricted catch-all to expose its whole catalog.
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

// TestRouter_SharedGatewayListingSurface prevents a shared host from advertising
// models through an API that their provider record does not support.
func TestRouter_SharedGatewayListingSurface(t *testing.T) {
	base := ProviderRoute{
		ID: "first", Vendor: "openai", Models: []string{"model-a"},
		UpstreamScheme: "https", UpstreamHost: "gateway.example.com",
		AllowedGroupIDs: []string{defaultTestGroup},
	}
	tests := []struct {
		name    string
		surface string
		vendor  string
		vendors []string
		models  []string
		want    []string
	}{
		{"matching vendor", "openai", "openai", nil, []string{"model-b"}, []string{"model-a", "model-b"}},
		{"matching vendors", "openai", "anthropic", []string{"openai", "anthropic"}, []string{"model-b"}, []string{"model-a", "model-b"}},
		{"incompatible vendor", "openai", "anthropic", nil, []string{"model-b"}, []string{"model-a"}},
		{"incompatible vendors", "openai", "", []string{"anthropic"}, []string{"model-b"}, []string{"model-a"}},
		{"incompatible catch-all", "openai", "anthropic", nil, nil, []string{"model-a"}},
		{"compatible catch-all", "openai", "", []string{"openai"}, nil, nil},
		{"unspecified surface", "", "anthropic", nil, []string{"model-b"}, []string{"model-a", "model-b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			other := base
			other.ID, other.Vendor, other.Vendors, other.Models = "other", tt.vendor, tt.vendors, tt.models
			mw := New(Config{Providers: []ProviderRoute{base, other}})
			in := newModellessInput(modelListingPath)
			in.Metadata = []middleware.KV{{Key: middleware.KeyLLMProvider, Value: tt.surface}}
			out, err := mw.Invoke(context.Background(), in)
			require.NoError(t, err)
			require.Equal(t, middleware.DecisionAllow, out.Decision, "authorized listing should pass")
			require.NotNil(t, out.Mutations)
			require.NotNil(t, out.Mutations.RewriteUpstream)
			assert.Equal(t, tt.want, out.Mutations.RewriteUpstream.DiscoveryModels,
				"only siblings supporting the requested API may contribute models or lift the bound")
		})
	}
}

// TestRouter_SharedGatewayListingMultipleGroups guards against losing a caller's
// secondary-group access or inheriting a different group's model allowlist.
func TestRouter_SharedGatewayListingMultipleGroups(t *testing.T) {
	first := ProviderRoute{
		ID: "first", Models: []string{"model-a", "restricted-a"},
		UpstreamScheme: "https", UpstreamHost: "gateway.example.com",
		AllowedGroupIDs: []string{defaultTestGroup, "private-team"},
		ModelPolicies: []ModelPolicyRule{
			{GroupIDs: []string{defaultTestGroup}, Models: []string{"model-a"}},
			{GroupIDs: []string{"private-team"}, Models: []string{"restricted-a"}},
		},
	}
	second := first
	second.ID = "second"
	second.Models = []string{"model-b", "restricted-b"}
	second.AllowedGroupIDs = []string{"grp-other", "private-team"}
	second.ModelPolicies = []ModelPolicyRule{
		{GroupIDs: []string{"grp-other"}, Models: []string{"model-b"}},
		{GroupIDs: []string{"private-team"}, Models: []string{"restricted-b"}},
	}
	private := first
	private.ID = "private"
	private.Models = []string{"private-model"}
	private.AllowedGroupIDs = []string{"private-team"}
	private.ModelPolicies = nil
	mw := New(Config{Providers: []ProviderRoute{first, second, private}})
	in := newModellessInput(modelListingPath)
	in.UserGroups = []string{defaultTestGroup, "grp-other"}
	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.Equal(t, middleware.DecisionAllow, out.Decision, "either group may authorize its own record")
	require.NotNil(t, out.Mutations)
	require.NotNil(t, out.Mutations.RewriteUpstream)
	assert.Equal(t, []string{"model-a", "model-b"}, out.Mutations.RewriteUpstream.DiscoveryModels,
		"both caller groups must contribute while private-team records and policies remain excluded")
}
