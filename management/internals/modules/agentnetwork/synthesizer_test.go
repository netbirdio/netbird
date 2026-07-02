package agentnetwork

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/status"
)

const (
	testAccountID = "acct-1"
	testCluster   = "eu.proxy.netbird.io"
	testSubdomain = "violet"
	testEndpoint  = "violet.eu.proxy.netbird.io"
)

func newSynthTestSettings() *types.Settings {
	return &types.Settings{
		AccountID: testAccountID,
		Cluster:   testCluster,
		Subdomain: testSubdomain,
	}
}

func newSynthTestProvider() *types.Provider {
	return &types.Provider{
		ID:                "prov-1",
		AccountID:         testAccountID,
		ProviderID:        "openai_api",
		Name:              "OpenAI",
		UpstreamURL:       "https://api.openai.com",
		APIKey:            "sk-test-key",
		Enabled:           true,
		Models:            []types.ProviderModel{{ID: "gpt-5.4", InputPer1k: 0.0025, OutputPer1k: 0.015}},
		SessionPrivateKey: "test-priv-key",
		SessionPublicKey:  "test-pub-key",
		CreatedAt:         time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func newSynthTestPolicy(providerID, sourceGroupID, guardrailID string) *types.Policy {
	policy := &types.Policy{
		ID:                     "pol-1",
		AccountID:              testAccountID,
		Name:                   "engineers",
		Enabled:                true,
		SourceGroups:           []string{sourceGroupID},
		DestinationProviderIDs: []string{providerID},
	}
	if guardrailID != "" {
		policy.GuardrailIDs = []string{guardrailID}
	}
	return policy
}

// expectSynthBaseInputs wires the four reads the new synthesiser issues
// in the happy path: settings, providers, policies, guardrails.
func expectSynthBaseInputs(mockStore *store.MockStore, ctx context.Context, settings *types.Settings, providers []*types.Provider, policies []*types.Policy, guardrails []*types.Guardrail) {
	if settings == nil {
		mockStore.EXPECT().
			GetAgentNetworkSettings(ctx, store.LockingStrengthNone, testAccountID).
			Return(nil, status.Errorf(status.NotFound, "agent network settings not found"))
		return
	}
	mockStore.EXPECT().
		GetAgentNetworkSettings(ctx, store.LockingStrengthNone, testAccountID).
		Return(settings, nil)
	mockStore.EXPECT().
		GetAccountAgentNetworkProviders(ctx, store.LockingStrengthNone, testAccountID).
		Return(providers, nil)
	if hasEnabled(providers) {
		mockStore.EXPECT().
			GetAccountAgentNetworkPolicies(ctx, store.LockingStrengthNone, testAccountID).
			Return(policies, nil)
		if hasEnabledPolicy(policies) {
			mockStore.EXPECT().
				GetAccountAgentNetworkGuardrails(ctx, store.LockingStrengthNone, testAccountID).
				Return(guardrails, nil)
		}
	}
}

func hasEnabled(providers []*types.Provider) bool {
	for _, p := range providers {
		if p != nil && p.Enabled {
			return true
		}
	}
	return false
}

func hasEnabledPolicy(policies []*types.Policy) bool {
	for _, p := range policies {
		if p != nil && p.Enabled {
			return true
		}
	}
	return false
}

func TestSynthesizeServices_HappyPath(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	openai := newSynthTestProvider()
	anthropic := &types.Provider{
		ID:                "prov-2",
		AccountID:         testAccountID,
		ProviderID:        "anthropic_api",
		Name:              "Anthropic",
		UpstreamURL:       "https://api.anthropic.com",
		APIKey:            "sk-ant-secret",
		Enabled:           true,
		Models:            []types.ProviderModel{{ID: "claude-opus-4-7"}},
		SessionPrivateKey: "ant-priv",
		SessionPublicKey:  "ant-pub",
		CreatedAt:         time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
	}

	policyEng := newSynthTestPolicy(openai.ID, "grp-eng", "")
	policyEng.ID = "pol-eng"
	policyOps := newSynthTestPolicy(anthropic.ID, "grp-ops", "")
	policyOps.ID = "pol-ops"

	expectSynthBaseInputs(mockStore, ctx, newSynthTestSettings(),
		[]*types.Provider{openai, anthropic},
		[]*types.Policy{policyEng, policyOps},
		[]*types.Guardrail{})

	services, err := SynthesizeServices(ctx, mockStore, testAccountID)
	require.NoError(t, err, "synthesis must succeed")
	require.Len(t, services, 1, "exactly one service per account")

	svc := services[0]
	assert.Equal(t, "agent-net-svc-acct-1", svc.ID, "service id is account-scoped")
	assert.Equal(t, testAccountID, svc.AccountID, "service inherits account ID")
	assert.Equal(t, testEndpoint, svc.Domain, "domain is settings.Endpoint() (subdomain.cluster)")
	assert.Equal(t, testCluster, svc.ProxyCluster, "proxy cluster comes from settings")
	assert.Equal(t, rpservice.ModeHTTP, svc.Mode, "synthesised services are HTTP mode")
	assert.True(t, svc.Private, "synthesised services are always private")
	assert.True(t, svc.Enabled, "synthesised services are enabled when emitted")
	assert.Equal(t, []string{"grp-eng", "grp-ops"}, svc.AccessGroups,
		"access groups union both policies' source groups (tunnel-peer auth)")

	require.Len(t, svc.Targets, 1, "single cluster target")
	target := svc.Targets[0]
	assert.Equal(t, rpservice.TargetTypeCluster, target.TargetType, "target type is cluster")
	assert.Equal(t, testCluster, target.TargetId, "target id is the cluster address")
	assert.Equal(t, "noop.invalid", target.Host, "host is the placeholder; router rewrites at request time")
	assert.Equal(t, uint16(443), target.Port, "placeholder port")
	assert.Equal(t, "https", target.Protocol, "placeholder scheme")
	assert.True(t, target.Options.DirectUpstream, "synth targets imply direct upstream")
	assert.True(t, target.Options.AgentNetwork, "synth targets must be flagged as agent_network")

	mws := target.Options.Middlewares
	require.Len(t, mws, 8, "eight middlewares: request_parser, router, limit_check, identity_inject, guardrail, limit_record, cost_meter, response_parser")
	assert.Equal(t, middlewareIDLLMRequestParser, mws[0].ID, "first middleware is the request parser")
	assert.Equal(t, rpservice.MiddlewareSlotOnRequest, mws[0].Slot, "request parser runs on_request")
	// Request parser carries the capture_prompt gate sourced from
	// settings.EnablePromptCollection. The synth-test settings default
	// EnablePromptCollection=false, so capture is off and the access-log row
	// will not carry prompt content.
	assert.JSONEq(t, `{"capture_prompt":false}`, string(mws[0].ConfigJSON), "request parser config must carry capture_prompt from synth")

	assert.Equal(t, middlewareIDLLMRouter, mws[1].ID, "second middleware is the router")
	assert.Equal(t, rpservice.MiddlewareSlotOnRequest, mws[1].Slot, "router runs on_request")
	assert.True(t, mws[1].CanMutate, "router must carry CanMutate=true; without it the framework drops the auth-header strip/inject AND the upstream rewrite, leaving the proxy to dial the placeholder noop.invalid")
	require.NotEmpty(t, mws[1].ConfigJSON, "router config JSON must be populated")

	var routerCfg routerConfig
	require.NoError(t, json.Unmarshal(mws[1].ConfigJSON, &routerCfg), "router config must unmarshal")
	require.Len(t, routerCfg.Providers, 2, "both providers must reach the router")
	assert.Equal(t, openai.ID, routerCfg.Providers[0].ID, "openai is first by created_at")
	assert.Equal(t, "Bearer sk-test-key", routerCfg.Providers[0].AuthHeaderValue, "openai auth header value substitutes the API key")
	assert.Equal(t, "Authorization", routerCfg.Providers[0].AuthHeaderName, "openai uses Authorization header")
	assert.Equal(t, "https", routerCfg.Providers[0].UpstreamScheme, "openai scheme")
	assert.Equal(t, "api.openai.com", routerCfg.Providers[0].UpstreamHost, "openai host")
	assert.Equal(t, []string{"grp-eng"}, routerCfg.Providers[0].AllowedGroupIDs, "openai inherits policyEng's source groups")
	assert.Equal(t, []string{"gpt-5.4"}, routerCfg.Providers[0].Models,
		"the provider's configured model IDs must reach the router route — otherwise the model never matches and llm_router denies model_not_routable")
	assert.Equal(t, anthropic.ID, routerCfg.Providers[1].ID, "anthropic follows openai by created_at")
	assert.Equal(t, "sk-ant-secret", routerCfg.Providers[1].AuthHeaderValue, "anthropic value is the raw API key")
	assert.Equal(t, "x-api-key", routerCfg.Providers[1].AuthHeaderName, "anthropic uses x-api-key header")
	assert.Equal(t, []string{"grp-ops"}, routerCfg.Providers[1].AllowedGroupIDs, "anthropic inherits policyOps' source groups")
	assert.Equal(t, []string{"claude-opus-4-7"}, routerCfg.Providers[1].Models, "anthropic's configured model ID must reach its route")

	assert.Equal(t, middlewareIDLLMLimitCheck, mws[2].ID,
		"limit_check sits between router and identity_inject so deny paths skip header-stamp work")
	assert.Equal(t, rpservice.MiddlewareSlotOnRequest, mws[2].Slot, "limit_check runs on_request")

	assert.Equal(t, middlewareIDLLMIdentityInject, mws[3].ID, "fourth middleware is identity inject")
	assert.Equal(t, rpservice.MiddlewareSlotOnRequest, mws[3].Slot, "identity inject runs on_request")
	assert.True(t, mws[3].CanMutate, "identity inject must carry CanMutate=true so its HeadersAdd / HeadersRemove pass the framework's mutation gate")
	require.NotEmpty(t, mws[3].ConfigJSON, "identity inject config JSON must be populated even when no provider needs injection")

	assert.Equal(t, middlewareIDLLMGuardrail, mws[4].ID, "fifth middleware is the guardrail")
	assert.Equal(t, rpservice.MiddlewareSlotOnRequest, mws[4].Slot, "guardrail runs on_request")
	require.NotEmpty(t, mws[4].ConfigJSON, "guardrail config JSON must be populated")

	assert.Equal(t, middlewareIDLLMLimitRecord, mws[5].ID,
		"limit_record sits FIRST in the response section so it RUNS LAST at runtime — needs cost_meter + response_parser to have stamped tokens / cost first")
	assert.Equal(t, rpservice.MiddlewareSlotOnResponse, mws[5].Slot, "limit_record runs on_response")

	assert.Equal(t, middlewareIDCostMeter, mws[6].ID, "seventh middleware is the cost meter")
	assert.Equal(t, rpservice.MiddlewareSlotOnResponse, mws[6].Slot, "cost meter runs on_response")
	assert.Equal(t, []byte("{}"), mws[6].ConfigJSON, "cost meter carries an explicit empty config")

	assert.Equal(t, middlewareIDLLMResponseParser, mws[7].ID, "eighth middleware is the response parser")
	assert.Equal(t, rpservice.MiddlewareSlotOnResponse, mws[7].Slot, "response parser runs on_response")
}

func TestSynthesizeServices_NoSettings_ReturnsNil(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	expectSynthBaseInputs(mockStore, ctx, nil, nil, nil, nil)

	services, err := SynthesizeServices(ctx, mockStore, testAccountID)
	require.NoError(t, err)
	assert.Empty(t, services, "missing settings row must yield no synth")
}

func TestSynthesizeServices_NoProviders_ReturnsNil(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	expectSynthBaseInputs(mockStore, ctx, newSynthTestSettings(), []*types.Provider{}, nil, nil)

	services, err := SynthesizeServices(ctx, mockStore, testAccountID)
	require.NoError(t, err)
	assert.Empty(t, services, "settings present but no providers must yield no synth")
}

func TestSynthesizeServices_DisabledProvider_NoService(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	provider := newSynthTestProvider()
	provider.Enabled = false

	expectSynthBaseInputs(mockStore, ctx, newSynthTestSettings(),
		[]*types.Provider{provider}, nil, nil)

	services, err := SynthesizeServices(ctx, mockStore, testAccountID)
	require.NoError(t, err)
	assert.Empty(t, services, "disabled provider must not synthesise a service")
}

func TestSynthesizeServices_DisabledPolicy_NoService(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	provider := newSynthTestProvider()
	policy := newSynthTestPolicy(provider.ID, "grp-eng", "")
	policy.Enabled = false

	expectSynthBaseInputs(mockStore, ctx, newSynthTestSettings(),
		[]*types.Provider{provider}, []*types.Policy{policy}, nil)

	services, err := SynthesizeServices(ctx, mockStore, testAccountID)
	require.NoError(t, err)
	assert.Empty(t, services, "disabled policy must not trigger synthesis")
}

func TestSynthesizeServices_RouterConfigOrdering(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	first := newSynthTestProvider()
	first.ID = "prov-first"
	first.CreatedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	second := newSynthTestProvider()
	second.ID = "prov-second"
	second.ProviderID = "anthropic_api"
	second.UpstreamURL = "https://api.anthropic.com"
	second.APIKey = "sk-ant"
	second.CreatedAt = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	third := newSynthTestProvider()
	third.ID = "prov-third"
	third.ProviderID = "mistral_api"
	third.UpstreamURL = "https://api.mistral.ai"
	third.APIKey = "sk-mistral"
	third.CreatedAt = time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	policy := newSynthTestPolicy(first.ID, "grp-eng", "")
	policy.DestinationProviderIDs = []string{first.ID, second.ID, third.ID}

	// Pass providers in shuffled order to confirm the synth sorts them.
	expectSynthBaseInputs(mockStore, ctx, newSynthTestSettings(),
		[]*types.Provider{second, first, third},
		[]*types.Policy{policy}, []*types.Guardrail{})

	services, err := SynthesizeServices(ctx, mockStore, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1)

	mws := services[0].Targets[0].Options.Middlewares
	var routerCfg routerConfig
	for _, m := range mws {
		if m.ID == middlewareIDLLMRouter {
			require.NoError(t, json.Unmarshal(m.ConfigJSON, &routerCfg))
			break
		}
	}
	require.Len(t, routerCfg.Providers, 3, "all three providers must be in the router config")
	assert.Equal(t, first.ID, routerCfg.Providers[0].ID, "providers ordered by created_at; first is earliest")
	assert.Equal(t, third.ID, routerCfg.Providers[1].ID, "second is mid")
	assert.Equal(t, second.ID, routerCfg.Providers[2].ID, "third is latest")
}

func TestSynthesizeServices_PolicyCheckConfig_UnionsSourceGroups(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	provider := newSynthTestProvider()

	policyA := newSynthTestPolicy(provider.ID, "grp-eng", "")
	policyA.ID = "pol-a"
	policyA.SourceGroups = []string{"grp-eng", "grp-shared"}
	policyB := newSynthTestPolicy(provider.ID, "grp-ops", "")
	policyB.ID = "pol-b"
	policyB.SourceGroups = []string{"grp-ops", "grp-shared"}

	expectSynthBaseInputs(mockStore, ctx, newSynthTestSettings(),
		[]*types.Provider{provider},
		[]*types.Policy{policyA, policyB},
		[]*types.Guardrail{})

	services, err := SynthesizeServices(ctx, mockStore, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1)

	mws := services[0].Targets[0].Options.Middlewares
	var routerCfg routerConfig
	for _, m := range mws {
		if m.ID == middlewareIDLLMRouter {
			require.NoError(t, json.Unmarshal(m.ConfigJSON, &routerCfg))
			break
		}
	}
	require.Len(t, routerCfg.Providers, 1, "single provider authorised by both policies")
	assert.Equal(t, provider.ID, routerCfg.Providers[0].ID)
	assert.Equal(t, []string{"grp-eng", "grp-ops", "grp-shared"}, routerCfg.Providers[0].AllowedGroupIDs,
		"source groups must be unioned and sorted; the duplicate grp-shared collapses")
}

func TestSynthesizeServices_OrphanProvider_HasEmptyAllowedGroups(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	authorised := newSynthTestProvider()
	authorised.ID = "prov-authed"

	orphan := newSynthTestProvider()
	orphan.ID = "prov-orphan"
	orphan.ProviderID = "anthropic_api"
	orphan.UpstreamURL = "https://api.anthropic.com"
	orphan.APIKey = "sk-ant"
	orphan.CreatedAt = time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)

	// Policy authorises the first provider only.
	policy := newSynthTestPolicy(authorised.ID, "grp-eng", "")

	expectSynthBaseInputs(mockStore, ctx, newSynthTestSettings(),
		[]*types.Provider{authorised, orphan},
		[]*types.Policy{policy},
		[]*types.Guardrail{})

	services, err := SynthesizeServices(ctx, mockStore, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1)

	mws := services[0].Targets[0].Options.Middlewares
	var routerCfg routerConfig
	for _, m := range mws {
		if m.ID == middlewareIDLLMRouter {
			require.NoError(t, json.Unmarshal(m.ConfigJSON, &routerCfg))
			break
		}
	}

	// Orphan providers are dropped from the router config entirely.
	// The router treats an empty AllowedGroupIDs as a catch-all (right
	// default for non-agent-network targets, wrong default here), so
	// we don't ship them at all. Peers attempting to call models only
	// the orphan claims see model_not_routable; peers calling models
	// shared with the authorised provider get routed there.
	require.Len(t, routerCfg.Providers, 1, "only the authorised provider reaches the router")
	assert.Equal(t, authorised.ID, routerCfg.Providers[0].ID,
		"authorised provider must be in router config")
	assert.Equal(t, []string{"grp-eng"}, routerCfg.Providers[0].AllowedGroupIDs,
		"authorised provider inherits the policy's source groups")
}

// TestSynthesizeServices_IdentityInject_LiteLLM pins that a LiteLLM
// provider lands in the identity-inject middleware's config with the
// catalog-defined LiteLLM headers, while a non-LiteLLM provider does
// not. Together they prove the middleware is a no-op for accounts that
// don't use LiteLLM and stamps identity for those that do.
func TestSynthesizeServices_IdentityInject_LiteLLM(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	openai := newSynthTestProvider()
	openai.ID = "prov-openai"

	litellm := newSynthTestProvider()
	litellm.ID = "prov-litellm"
	litellm.ProviderID = "litellm_proxy"
	litellm.UpstreamURL = "https://litellm.acme.example.com"
	litellm.APIKey = "sk-llm-master"
	litellm.CreatedAt = time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC)

	policyOpenAI := newSynthTestPolicy(openai.ID, "grp-eng", "")
	policyOpenAI.ID = "pol-openai"
	policyLiteLLM := newSynthTestPolicy(litellm.ID, "grp-eng", "")
	policyLiteLLM.ID = "pol-litellm"

	expectSynthBaseInputs(mockStore, ctx, newSynthTestSettings(),
		[]*types.Provider{openai, litellm},
		[]*types.Policy{policyOpenAI, policyLiteLLM},
		[]*types.Guardrail{})

	services, err := SynthesizeServices(ctx, mockStore, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1)

	mws := services[0].Targets[0].Options.Middlewares
	var injectCfg identityInjectConfig
	for _, m := range mws {
		if m.ID == middlewareIDLLMIdentityInject {
			require.NoError(t, json.Unmarshal(m.ConfigJSON, &injectCfg))
			break
		}
	}
	require.Len(t, injectCfg.Providers, 1,
		"only providers whose catalog entry declares IdentityInjection should appear in the inject config")
	entry := injectCfg.Providers[0]
	assert.Equal(t, litellm.ID, entry.ProviderID,
		"the LiteLLM provider must be the one identity-stamped, not the OpenAI direct provider")
	require.NotNil(t, entry.HeaderPair, "LiteLLM uses the HeaderPair shape")
	assert.Nil(t, entry.JSONMetadata, "shapes are mutually exclusive — JSONMetadata must be nil for HeaderPair providers")
	assert.Equal(t, "x-litellm-end-user-id", entry.HeaderPair.EndUserIDHeader,
		"end-user-id header must come from the catalog entry's IdentityInjection block")
	assert.Equal(t, "x-litellm-tags", entry.HeaderPair.TagsHeader)
}

// TestSynthesizeServices_IdentityInject_Bifrost_OperatorOverrides
// covers the customizable HeaderPair contract. The Bifrost catalog
// entry sets HeaderPair.Customizable=true with x-bf-dim-* defaults
// (placeholders surfaced by the dashboard, NOT authoritative at
// synth time). The wire header names that actually land on the
// inject middleware config come from the provider record's
// IdentityHeaderUserID / IdentityHeaderGroups fields verbatim. This
// lets operators pick between Bifrost's two attribution paths
// (always-on x-bf-lh-* logs metadata vs. label-declared x-bf-dim-*
// telemetry) per provider record without code changes.
//
// Three sub-cases under one fixture: full override, partial
// override (user kept, groups disabled), and ParserID empty so the
// proxy falls back to URL sniffing.
func TestSynthesizeServices_IdentityInject_Bifrost_OperatorOverrides(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	bifrost := newSynthTestProvider()
	bifrost.ID = "prov-bifrost"
	bifrost.ProviderID = "bifrost"
	bifrost.UpstreamURL = "https://bifrost.acme.example.com/openai/v1"
	bifrost.APIKey = "sk-bf-key"
	bifrost.IdentityHeaderUserID = "x-bf-lh-netbird_user_id"
	bifrost.IdentityHeaderGroups = "x-bf-lh-netbird_groups"
	bifrost.CreatedAt = time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC)

	policy := newSynthTestPolicy(bifrost.ID, "grp-eng", "")
	policy.ID = "pol-bifrost"

	expectSynthBaseInputs(mockStore, ctx, newSynthTestSettings(),
		[]*types.Provider{bifrost},
		[]*types.Policy{policy},
		[]*types.Guardrail{})

	services, err := SynthesizeServices(ctx, mockStore, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1)

	mws := services[0].Targets[0].Options.Middlewares
	var injectCfg identityInjectConfig
	for _, m := range mws {
		if m.ID == middlewareIDLLMIdentityInject {
			require.NoError(t, json.Unmarshal(m.ConfigJSON, &injectCfg))
			break
		}
	}
	require.Len(t, injectCfg.Providers, 1,
		"single bifrost catalog entry → one inject config target — operator's URL path picks the parser, not the catalog id")

	entry := injectCfg.Providers[0]
	assert.Equal(t, bifrost.ID, entry.ProviderID)
	require.NotNil(t, entry.HeaderPair, "Bifrost uses HeaderPair shape")
	assert.Equal(t, "x-bf-lh-netbird_user_id", entry.HeaderPair.EndUserIDHeader,
		"operator-set IdentityHeaderUserID overrides the catalog's x-bf-dim- placeholder — proves the Customizable flag actually swaps the source of truth")
	assert.Equal(t, "x-bf-lh-netbird_groups", entry.HeaderPair.TagsHeader,
		"operator-set IdentityHeaderGroups overrides the catalog's x-bf-dim- placeholder")
	assert.False(t, entry.HeaderPair.TagsInBody,
		"body-inject flags stay catalog-owned — Bifrost reads identity from headers, body inject would be a no-op")
	assert.False(t, entry.HeaderPair.EndUserIDInBody)
}

// TestSynthesizeServices_IdentityInject_Bifrost_PartialDisable proves
// that clearing one of the IdentityHeader* fields disables stamping
// for THAT dimension only, leaving the other dimension active.
// Critical because the customizable contract says "empty = disabled
// for that dimension"; if the synth path silently fell back to the
// catalog default for an empty operator value, operators couldn't
// turn off groups while keeping user id (or vice versa).
func TestSynthesizeServices_IdentityInject_Bifrost_PartialDisable(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	bifrost := newSynthTestProvider()
	bifrost.ID = "prov-bifrost"
	bifrost.ProviderID = "bifrost"
	bifrost.UpstreamURL = "https://bifrost.acme.example.com/openai/v1"
	bifrost.APIKey = "sk-bf-key"
	bifrost.IdentityHeaderUserID = "x-bf-lh-netbird_user_id"
	bifrost.IdentityHeaderGroups = "" // operator explicitly disabled groups
	bifrost.CreatedAt = time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC)

	policy := newSynthTestPolicy(bifrost.ID, "grp-eng", "")
	policy.ID = "pol-bifrost"

	expectSynthBaseInputs(mockStore, ctx, newSynthTestSettings(),
		[]*types.Provider{bifrost},
		[]*types.Policy{policy},
		[]*types.Guardrail{})

	services, err := SynthesizeServices(ctx, mockStore, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1)

	mws := services[0].Targets[0].Options.Middlewares
	var injectCfg identityInjectConfig
	for _, m := range mws {
		if m.ID == middlewareIDLLMIdentityInject {
			require.NoError(t, json.Unmarshal(m.ConfigJSON, &injectCfg))
			break
		}
	}
	require.Len(t, injectCfg.Providers, 1)
	entry := injectCfg.Providers[0]
	require.NotNil(t, entry.HeaderPair, "user-id header is still set so the rule fires")
	assert.Equal(t, "x-bf-lh-netbird_user_id", entry.HeaderPair.EndUserIDHeader)
	assert.Empty(t, entry.HeaderPair.TagsHeader,
		"groups header must be empty — operator cleared it; the inject middleware no-ops on empty header names so groups are NOT stamped")
}

// TestSynthesizeServices_IdentityInject_Cloudflare_OperatorOverrides
// covers the JSONMetadata customizable contract: Cloudflare's
// catalog entry sets JSONMetadata.Customizable=true with
// netbird_user_id / netbird_groups defaults that the dashboard
// surfaces as placeholders. The actual JSON keys that land inside
// the cf-aig-metadata header come from the provider record's
// IdentityHeaderUserID / IdentityHeaderGroups fields. Reuses the
// same fields HeaderPair customizable does — the dimensions
// (user identity, groups) match; only the wire encoding (JSON key
// vs HTTP header name) differs.
func TestSynthesizeServices_IdentityInject_Cloudflare_OperatorOverrides(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	cf := newSynthTestProvider()
	cf.ID = "prov-cf"
	cf.ProviderID = "cloudflare_ai_gateway"
	cf.UpstreamURL = "https://gateway.ai.cloudflare.com/v1/acct-xyz/my-gateway/openai"
	cf.APIKey = "cf-aig-token"
	cf.IdentityHeaderUserID = "team_member"
	cf.IdentityHeaderGroups = "team_groups"
	cf.CreatedAt = time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC)

	policy := newSynthTestPolicy(cf.ID, "grp-eng", "")
	policy.ID = "pol-cf"

	expectSynthBaseInputs(mockStore, ctx, newSynthTestSettings(),
		[]*types.Provider{cf},
		[]*types.Policy{policy},
		[]*types.Guardrail{})

	services, err := SynthesizeServices(ctx, mockStore, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1)

	mws := services[0].Targets[0].Options.Middlewares
	var injectCfg identityInjectConfig
	for _, m := range mws {
		if m.ID == middlewareIDLLMIdentityInject {
			require.NoError(t, json.Unmarshal(m.ConfigJSON, &injectCfg))
			break
		}
	}
	require.Len(t, injectCfg.Providers, 1)
	entry := injectCfg.Providers[0]
	require.NotNil(t, entry.JSONMetadata, "Cloudflare uses JSONMetadata shape — single header carrying a JSON object")
	assert.Nil(t, entry.HeaderPair, "shapes are mutually exclusive")
	assert.Equal(t, "cf-aig-metadata", entry.JSONMetadata.Header,
		"the wire header is catalog-owned (cf-aig-metadata) — operator can rename the JSON keys but not the header itself")
	assert.Equal(t, "team_member", entry.JSONMetadata.UserKey,
		"operator-set IdentityHeaderUserID overrides the catalog's netbird_user_id default — proves the JSONMetadata Customizable flag swaps the source of truth like HeaderPair already does")
	assert.Equal(t, "team_groups", entry.JSONMetadata.GroupsKey,
		"operator-set IdentityHeaderGroups overrides the catalog's netbird_groups default")
}

// TestSynthesizeServices_IdentityInject_Portkey_NotCustomizable
// is the JSONMetadata negative case: Portkey's catalog entry leaves
// Customizable=false because Portkey's analytics dashboard reserves
// "_user" and "groups" as fixed JSON keys. An operator-set
// IdentityHeader* on a Portkey provider record must NOT override
// those keys, or Portkey's per-user filters silently break.
func TestSynthesizeServices_IdentityInject_Portkey_NotCustomizable(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	portkey := newSynthTestProvider()
	portkey.ID = "prov-portkey"
	portkey.ProviderID = "portkey"
	portkey.UpstreamURL = "https://api.portkey.ai/v1"
	portkey.APIKey = "portkey-account-key"
	// Operator set these — but portkey's catalog entry has
	// JSONMetadata.Customizable=false, so synth must IGNORE them
	// and stick with the catalog's _user / groups defaults.
	portkey.IdentityHeaderUserID = "should-be-ignored"
	portkey.IdentityHeaderGroups = "should-be-ignored-too"
	portkey.CreatedAt = time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC)

	policy := newSynthTestPolicy(portkey.ID, "grp-eng", "")
	policy.ID = "pol-portkey"

	expectSynthBaseInputs(mockStore, ctx, newSynthTestSettings(),
		[]*types.Provider{portkey},
		[]*types.Policy{policy},
		[]*types.Guardrail{})

	services, err := SynthesizeServices(ctx, mockStore, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1)

	mws := services[0].Targets[0].Options.Middlewares
	var injectCfg identityInjectConfig
	for _, m := range mws {
		if m.ID == middlewareIDLLMIdentityInject {
			require.NoError(t, json.Unmarshal(m.ConfigJSON, &injectCfg))
			break
		}
	}
	require.Len(t, injectCfg.Providers, 1)
	entry := injectCfg.Providers[0]
	require.NotNil(t, entry.JSONMetadata)
	assert.Equal(t, "_user", entry.JSONMetadata.UserKey,
		"Portkey's reserved JSON key must hold — Customizable=false on the catalog blocks the operator's override fields")
	assert.Equal(t, "groups", entry.JSONMetadata.GroupsKey,
		"same fixed-schema guarantee for the groups dimension")
}

// TestSynthesizeServices_IdentityInject_Vercel pins Vercel AI
// Gateway's wiring: HeaderPair shape with fixed wire names dictated
// by Vercel's Custom Reporting API (ai-reporting-user /
// ai-reporting-tags). Customizable=false on the catalog entry, so
// the synth path takes the catalog values verbatim and ignores any
// IdentityHeader* fields the operator might have set. Renaming
// these headers would just silently disable attribution — Vercel's
// reporting endpoint only matches the canonical names — so the
// fixed contract is the right semantic.
func TestSynthesizeServices_IdentityInject_Vercel(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	vercel := newSynthTestProvider()
	vercel.ID = "prov-vercel"
	vercel.ProviderID = "vercel_ai_gateway"
	vercel.UpstreamURL = "https://ai-gateway.vercel.sh/v1"
	vercel.APIKey = "vrc-team-key"
	// Operator set these — they MUST be ignored because Vercel's
	// catalog entry is non-customizable. Renaming the headers on
	// the wire would defeat Vercel's reporting endpoint.
	vercel.IdentityHeaderUserID = "should-be-ignored"
	vercel.IdentityHeaderGroups = "should-be-ignored-too"
	vercel.CreatedAt = time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC)

	policy := newSynthTestPolicy(vercel.ID, "grp-eng", "")
	policy.ID = "pol-vercel"

	expectSynthBaseInputs(mockStore, ctx, newSynthTestSettings(),
		[]*types.Provider{vercel},
		[]*types.Policy{policy},
		[]*types.Guardrail{})

	services, err := SynthesizeServices(ctx, mockStore, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1)

	mws := services[0].Targets[0].Options.Middlewares
	var injectCfg identityInjectConfig
	for _, m := range mws {
		if m.ID == middlewareIDLLMIdentityInject {
			require.NoError(t, json.Unmarshal(m.ConfigJSON, &injectCfg))
			break
		}
	}
	require.Len(t, injectCfg.Providers, 1)
	entry := injectCfg.Providers[0]
	require.NotNil(t, entry.HeaderPair, "Vercel uses HeaderPair shape — separate ai-reporting-user / ai-reporting-tags headers, not a JSON blob")
	assert.Nil(t, entry.JSONMetadata, "shapes are mutually exclusive")
	assert.Equal(t, "ai-reporting-user", entry.HeaderPair.EndUserIDHeader,
		"end-user-id header must be Vercel's canonical ai-reporting-user — renaming would silently disable attribution at Vercel's Custom Reporting endpoint")
	assert.Equal(t, "ai-reporting-tags", entry.HeaderPair.TagsHeader,
		"tags header must be Vercel's canonical ai-reporting-tags for the same reason")
	assert.False(t, entry.HeaderPair.TagsInBody,
		"Vercel reads from headers — body inject would be a LiteLLM-specific belt-and-suspenders unneeded here")
	assert.False(t, entry.HeaderPair.EndUserIDInBody)
}

// TestSynthesizeServices_IdentityInject_OpenRouter pins OpenRouter's
// wiring: HeaderPair shape with body-only injection. OpenRouter's
// per-user attribution is the OpenAI-standard `user` body field —
// there's no header path and no groups dimension at all. The catalog
// entry sets EndUserIDInBody=true with empty header names; the inject
// middleware writes user identity into the request body but stamps
// nothing on the header surface. Customizable=false so any operator
// IdentityHeader* fields are ignored.
//
// Also asserts the static ExtraHeaders surface: operators provide
// their app URL and display name on the provider record (HTTP-Referer
// and X-OpenRouter-Title), and these land on every upstream request
// so OpenRouter's app rankings / analytics attribute correctly.
func TestSynthesizeServices_IdentityInject_OpenRouter(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	openrouter := newSynthTestProvider()
	openrouter.ID = "prov-openrouter"
	openrouter.ProviderID = "openrouter"
	openrouter.UpstreamURL = "https://openrouter.ai/api/v1"
	openrouter.APIKey = "sk-or-v1-acme"
	// These would only apply if the catalog entry was Customizable;
	// it isn't, so they must be IGNORED.
	openrouter.IdentityHeaderUserID = "should-be-ignored"
	openrouter.IdentityHeaderGroups = "should-be-ignored-too"
	openrouter.ExtraValues = map[string]string{
		"HTTP-Referer":       "https://acme.example/agents",
		"X-OpenRouter-Title": "Acme Agents",
	}
	openrouter.CreatedAt = time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC)

	policy := newSynthTestPolicy(openrouter.ID, "grp-eng", "")
	policy.ID = "pol-openrouter"

	expectSynthBaseInputs(mockStore, ctx, newSynthTestSettings(),
		[]*types.Provider{openrouter},
		[]*types.Policy{policy},
		[]*types.Guardrail{})

	services, err := SynthesizeServices(ctx, mockStore, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1)

	mws := services[0].Targets[0].Options.Middlewares
	var injectCfg identityInjectConfig
	for _, m := range mws {
		if m.ID == middlewareIDLLMIdentityInject {
			require.NoError(t, json.Unmarshal(m.ConfigJSON, &injectCfg))
			break
		}
	}
	require.Len(t, injectCfg.Providers, 1)
	entry := injectCfg.Providers[0]
	require.NotNil(t, entry.HeaderPair, "OpenRouter uses HeaderPair shape — body-inject is the only branch active")
	assert.Empty(t, entry.HeaderPair.EndUserIDHeader,
		"OpenRouter does not document a header path for per-user identity; the inject must NOT stamp a header here. Customizable=false means operator IdentityHeader* fields are ignored.")
	assert.Empty(t, entry.HeaderPair.TagsHeader,
		"OpenRouter has no per-request groups / tags dimension — the tags header MUST stay empty")
	assert.True(t, entry.HeaderPair.EndUserIDInBody,
		"OpenRouter's only per-user attribution path is the OpenAI-standard `user` body field — body inject is the load-bearing piece for this provider")
	assert.False(t, entry.HeaderPair.TagsInBody,
		"no tags dimension at all → no tags-in-body either")

	// ExtraHeaders carry the operator-typed app URL + display name to
	// OpenRouter's app rankings. The synth must echo BOTH static
	// header values with the operator's typed strings.
	require.Len(t, entry.ExtraHeaders, 2,
		"both ExtraHeaders the catalog declares should land on the inject config when the operator filled in values")
	byName := map[string]string{}
	for _, h := range entry.ExtraHeaders {
		byName[h.Name] = h.Value
	}
	assert.Equal(t, "https://acme.example/agents", byName["HTTP-Referer"],
		"HTTP-Referer is OpenRouter's primary app identifier — must round-trip the operator-typed URL verbatim")
	assert.Equal(t, "Acme Agents", byName["X-OpenRouter-Title"],
		"X-OpenRouter-Title surfaces as the app's display name in OpenRouter's rankings — must round-trip operator's chosen string")
}

// TestSynthesizeServices_IdentityInject_NonCustomizable_UsesCatalog
// is the LiteLLM-style negative case: when the catalog entry does
// NOT flag HeaderPair as Customizable, the catalog defaults are
// authoritative and any IdentityHeader* values on the provider
// record are ignored. Without this guard, an operator who set those
// fields on a non-Bifrost provider could accidentally break the
// gateway's wire protocol (LiteLLM only honours x-litellm-end-user-
// id; renaming it would silently drop spend tracking).
func TestSynthesizeServices_IdentityInject_NonCustomizable_UsesCatalog(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	litellm := newSynthTestProvider()
	litellm.ID = "prov-litellm"
	litellm.ProviderID = "litellm_proxy"
	litellm.UpstreamURL = "https://litellm.acme.example.com"
	litellm.APIKey = "sk-llm-master"
	// Operator set these — but litellm_proxy's catalog entry has
	// HeaderPair.Customizable=false, so the synth path must IGNORE
	// these and fall back to the catalog defaults.
	litellm.IdentityHeaderUserID = "x-bf-lh-should-be-ignored"
	litellm.IdentityHeaderGroups = "x-bf-lh-should-be-ignored-too"
	litellm.CreatedAt = time.Date(2026, 4, 2, 0, 0, 0, 0, time.UTC)

	policy := newSynthTestPolicy(litellm.ID, "grp-eng", "")
	policy.ID = "pol-litellm"

	expectSynthBaseInputs(mockStore, ctx, newSynthTestSettings(),
		[]*types.Provider{litellm},
		[]*types.Policy{policy},
		[]*types.Guardrail{})

	services, err := SynthesizeServices(ctx, mockStore, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1)

	mws := services[0].Targets[0].Options.Middlewares
	var injectCfg identityInjectConfig
	for _, m := range mws {
		if m.ID == middlewareIDLLMIdentityInject {
			require.NoError(t, json.Unmarshal(m.ConfigJSON, &injectCfg))
			break
		}
	}
	require.Len(t, injectCfg.Providers, 1)
	entry := injectCfg.Providers[0]
	require.NotNil(t, entry.HeaderPair)
	assert.Equal(t, "x-litellm-end-user-id", entry.HeaderPair.EndUserIDHeader,
		"Customizable=false on the catalog entry must hold — operator IdentityHeader* fields cannot rename a fixed wire protocol's headers")
	assert.Equal(t, "x-litellm-tags", entry.HeaderPair.TagsHeader,
		"Customizable=false on the catalog entry must hold for tags too")
}

func TestSynthesizeServices_GuardrailMerge_AllowlistUnion_LimitsRestrictive(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	provider := newSynthTestProvider()

	guardrailA := &types.Guardrail{
		ID:        "g-a",
		AccountID: testAccountID,
		Checks: types.GuardrailChecks{
			ModelAllowlist: types.GuardrailModelAllowlist{Enabled: true, Models: []string{"gpt-5.4-mini"}},
		},
	}
	guardrailB := &types.Guardrail{
		ID:        "g-b",
		AccountID: testAccountID,
		Checks: types.GuardrailChecks{
			ModelAllowlist: types.GuardrailModelAllowlist{Enabled: true, Models: []string{"gpt-5.4-pro"}},
		},
	}

	policyA := newSynthTestPolicy(provider.ID, "grp-a", guardrailA.ID)
	policyA.ID = "pol-a"
	policyB := newSynthTestPolicy(provider.ID, "grp-b", guardrailB.ID)
	policyB.ID = "pol-b"

	expectSynthBaseInputs(mockStore, ctx, newSynthTestSettings(),
		[]*types.Provider{provider},
		[]*types.Policy{policyA, policyB},
		[]*types.Guardrail{guardrailA, guardrailB})

	services, err := SynthesizeServices(ctx, mockStore, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1)

	mws := services[0].Targets[0].Options.Middlewares
	var guardrailJSON []byte
	for _, m := range mws {
		if m.ID == middlewareIDLLMGuardrail {
			guardrailJSON = m.ConfigJSON
			break
		}
	}
	require.NotEmpty(t, guardrailJSON, "guardrail middleware config JSON must be present")

	var cfg guardrailConfig
	require.NoError(t, json.Unmarshal(guardrailJSON, &cfg), "guardrail config must unmarshal cleanly")
	assert.ElementsMatch(t, []string{"gpt-5.4-mini", "gpt-5.4-pro"}, cfg.ModelAllowlist,
		"model allowlist union must keep both models")
}

func TestSynthesizeServices_BackfillsMissingSessionKeys(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	provider := newSynthTestProvider()
	provider.SessionPrivateKey = ""
	provider.SessionPublicKey = ""
	policy := newSynthTestPolicy(provider.ID, "grp-eng", "")

	mockStore.EXPECT().
		GetAgentNetworkSettings(ctx, store.LockingStrengthNone, testAccountID).
		Return(newSynthTestSettings(), nil)
	mockStore.EXPECT().
		GetAccountAgentNetworkProviders(ctx, store.LockingStrengthNone, testAccountID).
		Return([]*types.Provider{provider}, nil)
	mockStore.EXPECT().
		GetAccountAgentNetworkPolicies(ctx, store.LockingStrengthNone, testAccountID).
		Return([]*types.Policy{policy}, nil)
	// Backfill must persist the new keys before synthesising.
	mockStore.EXPECT().
		SaveAgentNetworkProvider(ctx, gomock.Any()).
		DoAndReturn(func(_ context.Context, p *types.Provider) error {
			require.NotEmpty(t, p.SessionPrivateKey, "backfill must populate private key")
			require.NotEmpty(t, p.SessionPublicKey, "backfill must populate public key")
			return nil
		})
	mockStore.EXPECT().
		GetAccountAgentNetworkGuardrails(ctx, store.LockingStrengthNone, testAccountID).
		Return([]*types.Guardrail{}, nil)

	services, err := SynthesizeServices(ctx, mockStore, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1, "synthesis must complete after backfill")
	assert.NotEmpty(t, services[0].SessionPrivateKey, "synthesised service inherits the freshly-minted private key")
	assert.NotEmpty(t, services[0].SessionPublicKey, "synthesised service inherits the freshly-minted public key")
}

func TestSynthesizeServices_HTTPUpstream_KeepsExplicitPort(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	provider := newSynthTestProvider()
	provider.UpstreamURL = "http://internal-llm.lan:8080"
	policy := newSynthTestPolicy(provider.ID, "grp-eng", "")

	expectSynthBaseInputs(mockStore, ctx, newSynthTestSettings(),
		[]*types.Provider{provider},
		[]*types.Policy{policy},
		[]*types.Guardrail{})

	services, err := SynthesizeServices(ctx, mockStore, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1)

	mws := services[0].Targets[0].Options.Middlewares
	var routerCfg routerConfig
	for _, m := range mws {
		if m.ID == middlewareIDLLMRouter {
			require.NoError(t, json.Unmarshal(m.ConfigJSON, &routerCfg))
			break
		}
	}
	require.Len(t, routerCfg.Providers, 1)
	assert.Equal(t, "http", routerCfg.Providers[0].UpstreamScheme, "scheme follows the upstream URL")
	assert.Equal(t, "internal-llm.lan:8080", routerCfg.Providers[0].UpstreamHost,
		"explicit port travels with host so the router rewrite carries an authority the proxy can dial")
}

func TestSynthesizeServices_UpstreamURLPath_FlowsToRouter(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	// Provider configured with a path-prefixed upstream — common for
	// OpenAI-compatible endpoints behind corporate gateways. The path
	// is the router's disambiguator when two providers claim the same
	// model, so it must round-trip through buildRouterConfigJSON with
	// the trailing slash trimmed.
	provider := newSynthTestProvider()
	provider.UpstreamURL = "https://corp.example.com/openai/"
	policy := newSynthTestPolicy(provider.ID, "grp-eng", "")

	expectSynthBaseInputs(mockStore, ctx, newSynthTestSettings(),
		[]*types.Provider{provider},
		[]*types.Policy{policy},
		[]*types.Guardrail{})

	services, err := SynthesizeServices(ctx, mockStore, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1)

	mws := services[0].Targets[0].Options.Middlewares
	var routerCfg routerConfig
	for _, m := range mws {
		if m.ID == middlewareIDLLMRouter {
			require.NoError(t, json.Unmarshal(m.ConfigJSON, &routerCfg))
			break
		}
	}
	require.Len(t, routerCfg.Providers, 1)
	assert.Equal(t, "corp.example.com", routerCfg.Providers[0].UpstreamHost, "host should drop the path")
	assert.Equal(t, "/openai", routerCfg.Providers[0].UpstreamPath,
		"upstream path must be carried so the router can disambiguate same-model providers; trailing slash trimmed for stable string-prefix matching")
}

func TestSynthesizeServices_SkipTLSVerification_FlowsToRouter(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	// A provider fronting a self-hosted / internal gateway opts into skipping
	// upstream TLS verification; the synthesiser must carry it into the router
	// route so the proxy dials that upstream insecurely.
	provider := newSynthTestProvider()
	provider.SkipTLSVerification = true
	policy := newSynthTestPolicy(provider.ID, "grp-eng", "")

	expectSynthBaseInputs(mockStore, ctx, newSynthTestSettings(),
		[]*types.Provider{provider},
		[]*types.Policy{policy},
		[]*types.Guardrail{})

	services, err := SynthesizeServices(ctx, mockStore, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1)

	mws := services[0].Targets[0].Options.Middlewares
	var routerCfg routerConfig
	for _, m := range mws {
		if m.ID == middlewareIDLLMRouter {
			require.NoError(t, json.Unmarshal(m.ConfigJSON, &routerCfg))
			break
		}
	}
	require.Len(t, routerCfg.Providers, 1)
	assert.True(t, routerCfg.Providers[0].SkipTLSVerify,
		"provider skip_tls_verification must flow into the router route")
}

func TestSynthesizeServices_UnknownProviderID_FailsClosed(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	provider := newSynthTestProvider()
	provider.ProviderID = "nonexistent_provider"
	policy := newSynthTestPolicy(provider.ID, "grp-eng", "")

	expectSynthBaseInputs(mockStore, ctx, newSynthTestSettings(),
		[]*types.Provider{provider},
		[]*types.Policy{policy},
		[]*types.Guardrail{})

	_, err := SynthesizeServices(ctx, mockStore, testAccountID)
	require.Error(t, err, "synthesis must fail when the catalog can't resolve the provider id")
	assert.Contains(t, err.Error(), "unknown catalog id", "error must surface the misconfiguration")
}

func TestSynthesizeServices_EmptyAPIKey_FailsClosed(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	provider := newSynthTestProvider()
	provider.APIKey = ""
	policy := newSynthTestPolicy(provider.ID, "grp-eng", "")

	expectSynthBaseInputs(mockStore, ctx, newSynthTestSettings(),
		[]*types.Provider{provider},
		[]*types.Policy{policy},
		[]*types.Guardrail{})

	_, err := SynthesizeServices(ctx, mockStore, testAccountID)
	require.Error(t, err, "synthesis must refuse a provider with no api key")
	assert.Contains(t, err.Error(), "no api key", "error must surface the missing credential")
}
