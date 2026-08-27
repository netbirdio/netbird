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

// TestValidate_ABlankApiKeyIsNotTheSameAsAnOmittedOne covers the one shape the
// manager's own guard cannot see. Provider.FromAPIRequest assigns the key only
// when it trims to something, so a request carrying "   " arrives at
// UpdateProvider indistinguishable from one that omitted it — the stored
// credential is kept and the write answers 200, telling an operator who thinks
// they just rotated a key that it worked.
//
// The request still knows the difference, so the refusal belongs here.
func TestValidate_ABlankApiKeyIsNotTheSameAsAnOmittedOne(t *testing.T) {
	req := func(key *string) *api.AgentNetworkProviderRequest {
		return &api.AgentNetworkProviderRequest{
			ProviderId:  "openai_api",
			Name:        "OpenAI",
			UpstreamUrl: "https://api.openai.com",
			ApiKey:      key,
		}
	}

	blank := "   "
	err := validate(req(&blank), false)
	require.Error(t, err, "a blank api_key on update must not be read as 'keep what is stored'")
	assert.Contains(t, err.Error(), "api_key")

	require.NoError(t, validate(req(nil), false), "an omitted api_key is how an update keeps the stored credential")

	// Create already refuses this, and keeps its own message: a caller who sent
	// no usable key is told the field is required rather than being told how to
	// preserve a credential that does not exist yet.
	err = validate(req(&blank), true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api_key is required")
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

	// A private upstream: the save-time credential check leaves it unchecked
	// rather than spending "sk-test" against the real api.openai.com, which
	// the vendor refuses.
	create := `{
        "provider_id": "openai_api",
        "name": "openai",
        "upstream_url": "https://10.255.255.1",
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
	update := `{"provider_id": "openai_api", "name": "openai-renamed", "upstream_url": "https://10.255.255.1", "enabled": true}`
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
