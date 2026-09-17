package proxy

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_router"
)

func TestModelDiscoveryFilter_SharedGatewayRecords(t *testing.T) {
	first := llm_router.ProviderRoute{
		ID: "first", Models: []string{"model-a"},
		UpstreamScheme: "https", UpstreamHost: "gateway.example.com",
		AuthHeaderName: "Authorization", AuthHeaderValue: "Bearer test-key",
		AllowedGroupIDs: []string{"team"},
	}
	second := first
	second.ID = "second"
	second.Models = []string{"model-b", "restricted"}
	second.ModelPolicies = []llm_router.ModelPolicyRule{
		{GroupIDs: []string{"team"}, Models: []string{"model-b"}},
	}
	otherTeam := first
	otherTeam.ID = "other-team"
	otherTeam.Models = []string{"private-model"}
	otherTeam.AllowedGroupIDs = []string{"other-team"}
	router := llm_router.New(llm_router.Config{Providers: []llm_router.ProviderRoute{first, second, otherTeam}})
	out, err := router.Invoke(context.Background(), &middleware.Input{
		Slot: middleware.SlotOnRequest, Method: http.MethodGet,
		URL: "https://agent.example.com/v1/models", UserGroups: []string{"team"},
	})
	require.NoError(t, err)
	require.Equal(t, middleware.DecisionAllow, out.Decision, "authorized model listing should pass")
	require.NotNil(t, out.Mutations)
	require.NotNil(t, out.Mutations.RewriteUpstream)

	// Exercise the router's bound against the bytes the shared gateway returns.
	// All records see the same upstream listing, but only two models are usable.
	body := `{"object":"list","data":[{"id":"model-a"},{"id":"model-b"},{"id":"restricted"},{"id":"private-model"},{"id":"unconfigured"}]}`
	assert.Equal(t, []string{"model-a", "model-b"},
		listedIDs(t, out.Mutations.RewriteUpstream.DiscoveryModels, body),
		"the client must see every authorized family and no unauthorized models")
}
