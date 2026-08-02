package handlers

import (
	"encoding/json"
	"math"
	nethttp "net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/http/api"
)

func f(v float64) *float64 { return &v }

// TestValidate_ModelRates guards the single ingress point for operator-entered
// pricing. These rates flow verbatim into the proxy's cost_meter config at
// synthesis time; the proxy treats a bad rate as a chain-build failure, so
// rejecting here is what keeps an account's gateway from going down.
func TestValidate_ModelRates(t *testing.T) {
	base := func(models ...api.AgentNetworkProviderModel) *api.AgentNetworkProviderRequest {
		key := "sk-test"
		return &api.AgentNetworkProviderRequest{
			ProviderId:  "openai_api",
			Name:        "OpenAI",
			UpstreamUrl: "https://api.openai.com",
			ApiKey:      &key,
			Models:      &models,
		}
	}

	valid := api.AgentNetworkProviderModel{
		Id: "gpt-4o", InputPer1k: 0.0025, OutputPer1k: 0.01,
		CachedInputPer1k: f(0.00125),
	}
	require.NoError(t, validate(base(valid), true), "finite non-negative rates must pass")

	zeroRates := api.AgentNetworkProviderModel{Id: "self-hosted-llama", InputPer1k: 0, OutputPer1k: 0}
	require.NoError(t, validate(base(zeroRates), true), "explicit zero prices are allowed (free / self-hosted models)")

	cases := map[string]api.AgentNetworkProviderModel{
		"empty id":           {Id: "  ", InputPer1k: 0.001, OutputPer1k: 0.002},
		"negative input":     {Id: "m", InputPer1k: -0.001, OutputPer1k: 0.002},
		"negative output":    {Id: "m", InputPer1k: 0.001, OutputPer1k: -0.002},
		"NaN input":          {Id: "m", InputPer1k: math.NaN(), OutputPer1k: 0.002},
		"Inf output":         {Id: "m", InputPer1k: 0.001, OutputPer1k: math.Inf(1)},
		"negative cached":    {Id: "m", InputPer1k: 0.001, OutputPer1k: 0.002, CachedInputPer1k: f(-1)},
		"NaN cache read":     {Id: "m", InputPer1k: 0.001, OutputPer1k: 0.002, CacheReadPer1k: f(math.NaN())},
		"Inf cache creation": {Id: "m", InputPer1k: 0.001, OutputPer1k: 0.002, CacheCreationPer1k: f(math.Inf(-1))},
	}
	for name, m := range cases {
		assert.Error(t, validate(base(m), true), "case %q must be rejected", name)
	}
}

// TestProviderHandler_UpdateReplacesFullState pins the update contract shared
// with the other PUT endpoints: the request replaces the provider's mutable
// state, so optional fields absent from the JSON land as their zero values.
// The two exceptions are server-side: the api_key (a secret — omitted means
// "not rotated") and the session keypair, both preserved by the manager. The
// identity headers stay on the wire as explicit empty strings so a cleared
// value round-trips.
func TestProviderHandler_UpdateReplacesFullState(t *testing.T) {
	f := newAgentNetworkHandlerFixture(t)

	create := `{
        "provider_id": "openai_api",
        "name": "openai",
        "upstream_url": "https://api.openai.com",
        "api_key": "sk-test",
        "enabled": true,
        "metadata_disabled": true,
        "skip_tls_verification": true,
        "extra_values": {"x-portkey-config": "pc-prod-3f2a"},
        "identity_header_user_id": "x-bf-dim-netbird_user_id",
        "models": [{"id": "gpt-4o", "input_per_1k": 0.0025, "output_per_1k": 0.01}]
    }`
	rec := f.do(t, nethttp.MethodPost, "/agent-network/providers", create)
	require.Equal(t, nethttp.StatusOK, rec.Code, "create must succeed: %s", rec.Body.String())

	var created api.AgentNetworkProvider
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &created))

	// Minimal update: only the required fields, no api_key. Everything
	// optional must land as its zero value.
	update := `{"provider_id": "openai_api", "name": "openai-renamed", "upstream_url": "https://api.openai.com", "enabled": true}`
	rec = f.do(t, nethttp.MethodPut, "/agent-network/providers/"+created.Id, update)
	require.Equal(t, nethttp.StatusOK, rec.Code, "update without api_key must succeed (key is preserved): %s", rec.Body.String())

	var updated api.AgentNetworkProvider
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updated))
	assert.Equal(t, "openai-renamed", updated.Name, "sent field must apply")
	assert.True(t, updated.Enabled, "sent field must apply")
	assert.False(t, updated.MetadataDisabled, "omitted metadata_disabled must land as false — PUT replaces the full state")
	assert.False(t, updated.SkipTlsVerification, "omitted skip_tls_verification must land as false")
	assert.Nil(t, updated.ExtraValues, "omitted extra_values must be cleared")
	assert.Equal(t, "", updated.IdentityHeaderUserId, "omitted identity header must be cleared yet stay on the wire")
	assert.Empty(t, updated.Models, "omitted models must be cleared")
	assert.Contains(t, rec.Body.String(), `"identity_header_user_id":""`,
		"cleared identity header must round-trip as an explicit empty string")
}
