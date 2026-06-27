package agentnetwork

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/store"
)

// decodeServiceGuardrailConfig pulls the llm_guardrail middleware config off the
// synthesised service's single target.
func decodeServiceGuardrailConfig(t *testing.T, svc *rpservice.Service) guardrailConfig {
	t.Helper()
	require.NotEmpty(t, svc.Targets, "synth service must carry a target")
	for _, mw := range svc.Targets[0].Options.Middlewares {
		if mw.ID == middlewareIDLLMGuardrail {
			var cfg guardrailConfig
			require.NoError(t, json.Unmarshal(mw.ConfigJSON, &cfg), "guardrail config must decode")
			return cfg
		}
	}
	t.Fatal("llm_guardrail middleware not present on synthesised service")
	return guardrailConfig{}
}

// decodeMiddlewareRawConfig returns the raw ConfigJSON bytes for the named
// middleware on the synth service's target, or fails the test.
func decodeMiddlewareRawConfig(t *testing.T, svc *rpservice.Service, id string) []byte {
	t.Helper()
	require.NotEmpty(t, svc.Targets, "synth service must carry a target")
	for _, mw := range svc.Targets[0].Options.Middlewares {
		if mw.ID == id {
			return mw.ConfigJSON
		}
	}
	t.Fatalf("middleware %q not present on synthesised service", id)
	return nil
}

// saveGuardrailAndPolicy persists a guardrail with prompt capture + redact + a
// model allowlist, referenced by one enabled policy. Shared by the GC-3 tests.
func saveGuardrailAndPolicy(t *testing.T, ctx context.Context, s store.Store, provider *types.Provider) {
	t.Helper()
	guardrail := &types.Guardrail{
		ID:        "ainguard-1",
		AccountID: testAccountID,
		Name:      "strict",
		Checks: types.GuardrailChecks{
			ModelAllowlist: types.GuardrailModelAllowlist{Enabled: true, Models: []string{"gpt-5.4"}},
			PromptCapture:  types.GuardrailPromptCapture{Enabled: true, RedactPii: true},
		},
	}
	require.NoError(t, s.SaveAgentNetworkGuardrail(ctx, guardrail))
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, newSynthTestPolicy(provider.ID, "grp-eng", guardrail.ID)))
}

// TestSynthesizeServices_RealStore_PromptCaptureAccountIsSoleControl is the
// GC-3 contract: the account master switch (EnablePromptCollection) is the
// SOLE control for capture enablement. Policy-level guardrail prompt_capture is
// ignored for enablement — operators don't need to attach a capture guardrail
// to a policy just to turn capture on for the account. Off by default.
func TestSynthesizeServices_RealStore_PromptCaptureAccountIsSoleControl(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	defer cleanup()

	// Account collection master switch OFF (default).
	require.NoError(t, s.SaveAgentNetworkSettings(ctx, newSynthTestSettings()))
	saveGuardrailAndPolicy(t, ctx, s, newSynthTestProvider())

	services, err := SynthesizeServices(ctx, s, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1)

	cfg := decodeServiceGuardrailConfig(t, services[0])
	assert.Equal(t, []string{"gpt-5.4"}, cfg.ModelAllowlist,
		"model allowlist is a pure policy guardrail and must always reach the config")
	assert.False(t, cfg.PromptCapture.Enabled,
		"prompt capture must be off when the account toggle is off, even with a capture-enabled guardrail")
}

// TestSynthesizeServices_RealStore_PromptCaptureFlowsWhenAccountOptsIn proves
// the account toggle is sufficient on its own — even with NO guardrail
// attached to the policy, capture fires when the account opts in. Redact is
// the OR of account + guardrail.
func TestSynthesizeServices_RealStore_PromptCaptureFlowsWhenAccountOptsIn(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	defer cleanup()

	settings := newSynthTestSettings()
	settings.EnablePromptCollection = true
	require.NoError(t, s.SaveAgentNetworkSettings(ctx, settings))

	// Save a provider and a policy with NO guardrails attached — proves the
	// account toggle is sufficient on its own.
	provider := newSynthTestProvider()
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, newSynthTestPolicy(provider.ID, "grp-eng", "")))

	services, err := SynthesizeServices(ctx, s, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1)

	cfg := decodeServiceGuardrailConfig(t, services[0])
	assert.True(t, cfg.PromptCapture.Enabled,
		"account toggle alone must enable capture; no guardrail attachment required")
}

// TestSynthesizeServices_RealStore_AccountRedactWithoutGuardrailRedact proves
// the redact OR-merge from the account side: account RedactPii on, guardrail
// redact off, capture on at both levels.
func TestSynthesizeServices_RealStore_AccountRedactWithoutGuardrailRedact(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	defer cleanup()

	settings := newSynthTestSettings()
	settings.EnablePromptCollection = true
	settings.RedactPii = true
	require.NoError(t, s.SaveAgentNetworkSettings(ctx, settings))

	provider := newSynthTestProvider()
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	guardrail := &types.Guardrail{
		ID:        "ainguard-noredact",
		AccountID: testAccountID,
		Name:      "capture-only",
		Checks: types.GuardrailChecks{
			PromptCapture: types.GuardrailPromptCapture{Enabled: true, RedactPii: false},
		},
	}
	require.NoError(t, s.SaveAgentNetworkGuardrail(ctx, guardrail))
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, newSynthTestPolicy(provider.ID, "grp-eng", guardrail.ID)))

	services, err := SynthesizeServices(ctx, s, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1)

	cfg := decodeServiceGuardrailConfig(t, services[0])
	assert.True(t, cfg.PromptCapture.Enabled, "capture on (account + guardrail)")
	assert.True(t, cfg.PromptCapture.RedactPii, "account RedactPii must apply even when the guardrail leaves it off (OR)")
}

// TestSynthesizeServices_RealStore_NoGuardrail_CaptureOff pins the default:
// with no guardrail referenced, the synth service's guardrail config has prompt
// capture disabled and an empty allowlist. This is the "off by default" baseline
// the account switch must preserve.
func TestSynthesizeServices_RealStore_NoGuardrail_CaptureOff(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	defer cleanup()

	require.NoError(t, s.SaveAgentNetworkSettings(ctx, newSynthTestSettings()))
	provider := newSynthTestProvider()
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, newSynthTestPolicy(provider.ID, "grp-eng", "")))

	services, err := SynthesizeServices(ctx, s, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1, "exactly one synth service expected")

	cfg := decodeServiceGuardrailConfig(t, services[0])
	assert.Empty(t, cfg.ModelAllowlist, "no guardrail → no allowlist")
	assert.False(t, cfg.PromptCapture.Enabled, "no guardrail → prompt capture off by default")
	assert.False(t, cfg.PromptCapture.RedactPii, "no guardrail → redact off by default")
}
