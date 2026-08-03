package handlers

import (
	"math"
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
