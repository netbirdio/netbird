package agentnetwork

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// TestSynthesizedService_WireShape locks down the proto shape that
// flows from the synthesizer through ToProtoMapping to the proxy.
// Drift between this test and what the proxy expects manifests as
// "service not matching" — the proxy receives a mapping but can't
// register an SNI/HTTP route from it.
func TestSynthesizedService_WireShape(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockStore := store.NewMockStore(ctrl)

	provider := newSynthTestProvider()
	policy := newSynthTestPolicy(provider.ID, "grp-eng", "")

	expectSynthBaseInputs(mockStore, ctx, newSynthTestSettings(),
		[]*types.Provider{provider},
		[]*types.Policy{policy},
		[]*types.Guardrail{})

	services, err := SynthesizeServices(ctx, mockStore, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1)

	svc := services[0]
	mapping := svc.ToProtoMapping(rpservice.Create, "test-token", proxy.OIDCValidationConfig{})

	// Identifiers — account-scoped service ID, settings-derived domain.
	assert.Equal(t, "agent-net-svc-acct-1", mapping.GetId(), "stable account-scoped virtual service ID")
	assert.Equal(t, testAccountID, mapping.GetAccountId(), "account id round-trips")
	assert.Equal(t, testEndpoint, mapping.GetDomain(), "domain matches settings.Endpoint() output")

	// Mode + listen port — addMapping at proxy/server.go switches on Mode.
	assert.Equal(t, "http", mapping.GetMode(), "synthesised services are HTTP mode")
	assert.Equal(t, int32(0), mapping.GetListenPort(), "no custom listen port for HTTP services")

	// Auth token + private/tunnel shape: agent-network endpoints authenticate
	// inbound agents via ValidateTunnelPeer against AccessGroups, not OIDC.
	assert.Equal(t, "test-token", mapping.GetAuthToken(), "auth token round-trips for proxy CreateProxyPeer")
	assert.True(t, mapping.GetPrivate(), "synthesised services are private (tunnel-peer auth via AccessGroups)")
	require.NotNil(t, mapping.GetAuth(), "auth payload carries the session key")
	assert.False(t, mapping.GetAuth().GetOidc(), "OIDC is off for tunnel-auth agent-network services")

	// Path mappings — proxy/server.go::setupHTTPMapping early-returns when
	// len(mapping.GetPath()) == 0, so this is a critical assertion.
	require.Len(t, mapping.GetPath(), 1, "exactly one path mapping for the cluster target")
	pm := mapping.GetPath()[0]
	assert.Equal(t, "/", pm.GetPath(), "default path is '/'")
	assert.Equal(t, "https://noop.invalid/", pm.GetTarget(),
		"target URL is the placeholder; the router middleware rewrites it per request")
	require.NotNil(t, pm.GetOptions(), "target options must be populated so direct_upstream + middleware chain reach the proxy")
	assert.True(t, pm.GetOptions().GetDirectUpstream(), "synth targets imply direct_upstream so the proxy dials via the host stack")
	assert.True(t, pm.GetOptions().GetAgentNetwork(), "agent_network flag must travel on the wire so the proxy can tag access logs")

	mws := pm.GetOptions().GetMiddlewares()
	require.Len(t, mws, 8, "eight middlewares reach the proxy: request_parser, router, limit_check, identity_inject, guardrail, limit_record, cost_meter, response_parser")

	assert.Equal(t, middlewareIDLLMRequestParser, mws[0].GetId(), "first middleware id")
	assert.Equal(t, proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_REQUEST, mws[0].GetSlot(), "request parser slot")

	assert.Equal(t, middlewareIDLLMRouter, mws[1].GetId(), "second middleware id")
	assert.Equal(t, proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_REQUEST, mws[1].GetSlot(), "router slot")
	require.NotEmpty(t, mws[1].GetConfigJson(), "router config must travel on the wire")
	var routerCfg routerConfig
	require.NoError(t, json.Unmarshal(mws[1].GetConfigJson(), &routerCfg), "router config decodes")
	require.Len(t, routerCfg.Providers, 1, "the only enabled provider reaches the router")
	assert.Equal(t, provider.ID, routerCfg.Providers[0].ID, "router provider id matches synth provider")
	assert.Equal(t, "Bearer sk-test-key", routerCfg.Providers[0].AuthHeaderValue,
		"openai catalog template substitutes the API key on the wire")

	assert.Equal(t, middlewareIDLLMLimitCheck, mws[2].GetId(),
		"limit_check runs after the router so the resolved provider id is available, before identity_inject so a deny doesn't pay the header-stamp cost")
	assert.Equal(t, proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_REQUEST, mws[2].GetSlot())

	assert.Equal(t, middlewareIDLLMIdentityInject, mws[3].GetId(), "fourth middleware id")
	assert.Equal(t, proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_REQUEST, mws[3].GetSlot(), "identity inject slot")
	require.NotEmpty(t, mws[3].GetConfigJson(), "identity inject config JSON must travel on the wire")

	assert.Equal(t, middlewareIDLLMGuardrail, mws[4].GetId(), "fifth middleware id")
	assert.Equal(t, proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_REQUEST, mws[4].GetSlot(), "guardrail slot")
	require.NotEmpty(t, mws[4].GetConfigJson(), "guardrail middleware config JSON must travel on the wire")

	assert.Equal(t, middlewareIDLLMLimitRecord, mws[5].GetId(),
		"limit_record sits FIRST in the response section so it RUNS LAST at runtime — slot order on the response leg is reverse-of-slice")
	assert.Equal(t, proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_RESPONSE, mws[5].GetSlot())

	assert.Equal(t, middlewareIDCostMeter, mws[6].GetId(), "seventh middleware id")
	assert.Equal(t, proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_RESPONSE, mws[6].GetSlot(), "cost meter slot")

	assert.Equal(t, middlewareIDLLMResponseParser, mws[7].GetId(), "eighth middleware id")
	assert.Equal(t, proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_RESPONSE, mws[7].GetSlot(), "response parser slot")
}
