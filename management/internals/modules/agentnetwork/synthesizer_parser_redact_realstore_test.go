package agentnetwork

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/store"
)

// parserRedactConfig mirrors the on-wire shape of the redact + capture knobs
// that both llm_request_parser and llm_response_parser unmarshal. We don't
// import the proxy-side packages from a management test (cross-module), so we
// decode the JSON directly and assert on the fields that are part of the
// synth contract.
type parserRedactConfig struct {
	RedactPii         bool  `json:"redact_pii,omitempty"`
	CapturePrompt     *bool `json:"capture_prompt,omitempty"`     // present only on the request parser
	CaptureCompletion *bool `json:"capture_completion,omitempty"` // present only on the response parser
}

// TestSynthesizeServices_RealStore_ParserConfigsCarryRedactPii is the
// management-side contract test for the request/response parser redaction
// wiring. When settings.RedactPii is true, the synthesised middleware chain
// MUST stamp redact_pii=true on both llm_request_parser and llm_response_parser
// configs — otherwise the parsers ship raw prompts / completions to the
// access log even though the account has opted in. This is exactly the live
// leak path that motivated the parser-side redaction in the first place.
func TestSynthesizeServices_RealStore_ParserConfigsCarryRedactPii(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	defer cleanup()

	settings := newSynthTestSettings()
	settings.RedactPii = true
	settings.EnablePromptCollection = true
	require.NoError(t, s.SaveAgentNetworkSettings(ctx, settings))

	provider := newSynthTestProvider()
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, newSynthTestPolicy(provider.ID, "grp-eng", "")))

	services, err := SynthesizeServices(ctx, s, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1, "exactly one synth service expected")

	for _, parserID := range []string{middlewareIDLLMRequestParser, middlewareIDLLMResponseParser} {
		raw := decodeMiddlewareRawConfig(t, services[0], parserID)
		var cfg parserRedactConfig
		require.NoError(t, json.Unmarshal(raw, &cfg), "%s config must be valid JSON", parserID)
		assert.True(t, cfg.RedactPii, "%s config must carry redact_pii=true when settings.RedactPii is on (otherwise the parser ships raw prompts/completions to the access log)", parserID)
	}
	// The capture flag is set explicitly to enable_prompt_collection on each
	// parser. With it on here, both must allow emission.
	reqCfg := decodeParserConfig(t, services[0], middlewareIDLLMRequestParser)
	require.NotNil(t, reqCfg.CapturePrompt, "request parser must carry an explicit capture_prompt")
	assert.True(t, *reqCfg.CapturePrompt, "capture_prompt=true when EnablePromptCollection=true")
	respCfg := decodeParserConfig(t, services[0], middlewareIDLLMResponseParser)
	require.NotNil(t, respCfg.CaptureCompletion, "response parser must carry an explicit capture_completion")
	assert.True(t, *respCfg.CaptureCompletion, "capture_completion=true when EnablePromptCollection=true")
}

// decodeParserConfig is a small helper around decodeMiddlewareRawConfig that
// also unmarshals into parserRedactConfig.
func decodeParserConfig(t *testing.T, svc *rpservice.Service, parserID string) parserRedactConfig {
	t.Helper()
	raw := decodeMiddlewareRawConfig(t, svc, parserID)
	var cfg parserRedactConfig
	require.NoError(t, json.Unmarshal(raw, &cfg), "%s config must be valid JSON", parserID)
	return cfg
}

// TestSynthesizeServices_RealStore_ParserConfigsSuppressCaptureWhenLogCollectionOnly
// is the contract test for the bug: enable_log_collection=true with
// enable_prompt_collection=false MUST result in capture_prompt=false on the
// request parser AND capture_completion=false on the response parser, so the
// access-log row stays metadata-only (provider, model, tokens, cost) and
// carries NO prompt input nor response output. Without this, operators who
// want billing-style logs end up with raw user prompts and model outputs in
// every access-log entry.
func TestSynthesizeServices_RealStore_ParserConfigsSuppressCaptureWhenLogCollectionOnly(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	defer cleanup()

	settings := newSynthTestSettings()
	settings.EnableLogCollection = true     // operator wants logs ON
	settings.EnablePromptCollection = false // but NOT content capture
	require.NoError(t, s.SaveAgentNetworkSettings(ctx, settings))

	provider := newSynthTestProvider()
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, newSynthTestPolicy(provider.ID, "grp-eng", "")))

	services, err := SynthesizeServices(ctx, s, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1)

	reqCfg := decodeParserConfig(t, services[0], middlewareIDLLMRequestParser)
	require.NotNil(t, reqCfg.CapturePrompt, "request parser must carry an explicit capture_prompt gate")
	assert.False(t, *reqCfg.CapturePrompt, "capture_prompt MUST be false when EnablePromptCollection is off — otherwise llm.request_prompt_raw leaks user input into the access log")

	respCfg := decodeParserConfig(t, services[0], middlewareIDLLMResponseParser)
	require.NotNil(t, respCfg.CaptureCompletion, "response parser must carry an explicit capture_completion gate")
	assert.False(t, *respCfg.CaptureCompletion, "capture_completion MUST be false when EnablePromptCollection is off — otherwise llm.response_completion leaks model output into the access log")
}

// TestSynthesizeServices_RealStore_ParserConfigsOmitRedactPiiWhenOff proves
// the inverse: with the account toggle off, the parser configs stay clean (no
// redact_pii field, which the parsers treat as zero / no redaction). This is
// the operator-opt-out path — the access log keeps raw prompts/completions
// for debugging until the operator opts in.
func TestSynthesizeServices_RealStore_ParserConfigsOmitRedactPiiWhenOff(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	defer cleanup()

	// Default settings: RedactPii = false.
	require.NoError(t, s.SaveAgentNetworkSettings(ctx, newSynthTestSettings()))
	provider := newSynthTestProvider()
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, newSynthTestPolicy(provider.ID, "grp-eng", "")))

	services, err := SynthesizeServices(ctx, s, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1)

	for _, parserID := range []string{middlewareIDLLMRequestParser, middlewareIDLLMResponseParser} {
		raw := decodeMiddlewareRawConfig(t, services[0], parserID)
		// Inspect the decoded JSON directly: a struct decode would also pass
		// if redact_pii were present-but-false. The contract is that the key
		// is omitted entirely while the account toggle is off.
		var rawCfg map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(raw, &rawCfg), "%s config must be valid JSON", parserID)
		assert.NotContains(t, rawCfg, "redact_pii",
			"%s config must omit redact_pii entirely while the account toggle is off", parserID)
	}
}
