package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/modeldiscovery"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// discoveryManagerStub records what the handler asked for and returns a canned
// answer. The Manager interface is embedded rather than implemented: only the
// one method is reachable from this handler, and a call to any other should
// fail loudly rather than silently return a zero value.
type discoveryManagerStub struct {
	agentnetwork.Manager

	gotReq      modeldiscovery.Request
	gotRecordID string
	models      []modeldiscovery.Model
	err         error
}

func (s *discoveryManagerStub) DiscoverProviderModels(
	_ context.Context, _, _ string, req modeldiscovery.Request, recordID string,
) ([]modeldiscovery.Model, error) {
	s.gotReq = req
	s.gotRecordID = recordID
	return s.models, s.err
}

// postDiscovery drives the handler with an authenticated request.
func postDiscovery(t *testing.T, stub *discoveryManagerStub, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := &handler{manager: stub}

	req := httptest.NewRequest(http.MethodPost, "/agent-network/catalog/providers/models", strings.NewReader(body))
	req = req.WithContext(nbcontext.SetUserAuthInContext(req.Context(), auth.UserAuth{
		AccountId: "acc-1",
		UserId:    "user-1",
	}))

	rec := httptest.NewRecorder()
	h.discoverProviderModels(rec, req)
	return rec
}

func TestDiscoverModelsReturnsTheVendorList(t *testing.T) {
	stub := &discoveryManagerStub{models: []modeldiscovery.Model{
		{ID: "eu.anthropic.claude-haiku-4-5-20251001-v1:0", Label: "EU Claude Haiku 4.5", PricingKnown: true},
		{ID: "global.cohere.embed-v4:0", Label: "Global Cohere Embed v4"},
	}}

	rec := postDiscovery(t, stub, `{
		"catalog_provider_id":"bedrock_api",
		"upstream_url":"https://bedrock-runtime.eu-central-1.amazonaws.com",
		"api_key":"aws-bearer"
	}`)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	var out api.AgentNetworkModelDiscoveryResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.Len(t, out.Models, 2)

	assert.Equal(t, "eu.anthropic.claude-haiku-4-5-20251001-v1:0", out.Models[0].Id)
	assert.True(t, out.Models[0].PricingKnown)
	// An unpriced model must say so rather than arriving indistinguishable
	// from a priced one: registering it silently would meter at zero.
	assert.False(t, out.Models[1].PricingKnown)

	assert.Equal(t, "bedrock_api", stub.gotReq.CatalogID)
	assert.Equal(t, "aws-bearer", stub.gotReq.APIKey)
	assert.Empty(t, stub.gotRecordID)
}

func TestDiscoverModelsUsesAStoredRecordWithoutAKey(t *testing.T) {
	stub := &discoveryManagerStub{}

	rec := postDiscovery(t, stub, `{"catalog_provider_id":"openai_api","provider_id":"prov-42"}`)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	// The dashboard refreshes a saved provider's list without ever holding
	// the credential, so the record id has to reach the manager.
	assert.Equal(t, "prov-42", stub.gotRecordID)
	assert.Empty(t, stub.gotReq.APIKey)
}

// TestDiscoverModelsRefusesMixedCredentials covers the case where a caller
// names a saved provider AND supplies a key. Accepting it would run an
// arbitrary credential under the identity of a record the caller may only be
// permitted to read.
func TestDiscoverModelsRefusesMixedCredentials(t *testing.T) {
	stub := &discoveryManagerStub{}

	rec := postDiscovery(t, stub, `{
		"catalog_provider_id":"openai_api",
		"provider_id":"prov-42",
		"api_key":"sk-attacker"
	}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Empty(t, stub.gotRecordID, "the request must be refused before it reaches the manager")
}

// TestDiscoverModelsReportsNoDiscoveryDistinctly matters because the caller
// falls back to the catalog's own model list on this outcome. Collapsing it
// into a generic 500 would turn "this provider has no listing endpoint" into
// "something went wrong", and the form would show an error instead of a list.
func TestDiscoverModelsReportsNoDiscoveryDistinctly(t *testing.T) {
	stub := &discoveryManagerStub{err: modeldiscovery.ErrNoDiscovery}

	rec := postDiscovery(t, stub, `{"catalog_provider_id":"litellm_proxy","upstream_url":"https://gw.example.com","api_key":"sk"}`)
	assert.Equal(t, http.StatusUnprocessableEntity, rec.Code)
}

func TestDiscoverModelsRejectsMalformedRequests(t *testing.T) {
	for name, body := range map[string]string{
		"not json":              `{`,
		"no catalog provider":   `{"api_key":"sk"}`,
		"blank catalog provide": `{"catalog_provider_id":"   ","api_key":"sk"}`,
	} {
		t.Run(name, func(t *testing.T) {
			stub := &discoveryManagerStub{}
			rec := postDiscovery(t, stub, body)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
		})
	}
}
