package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	protobuf "google.golang.org/protobuf/proto"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
	guardrail "github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_guardrail"
	internalproxy "github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestUpdateMappingBindsMiddlewareRevisionAcrossPolicyUpdates(t *testing.T) {
	oldUpstream := &targetAccessUpstream{}
	oldBackend := httptest.NewServer(oldUpstream)
	t.Cleanup(oldBackend.Close)
	newUpstream := &targetAccessUpstream{}
	newBackend := httptest.NewServer(newUpstream)
	t.Cleanup(newBackend.Close)

	runtime, _ := newTargetAccessRuntime(t)
	registry := middleware.NewRegistry()
	require.NoError(t, registry.Register(guardrail.Factory{}))
	manager := middleware.NewManager(0, nil, runtime.Logger)
	manager.SetResolver(middleware.NewResolver(registry))
	manager.SetLiveServiceCheck(runtime.isLiveService)
	t.Cleanup(manager.InvalidateAll)
	runtime.middlewareRegistry = registry
	runtime.middlewareManager = manager
	runtime.proxy = internalproxy.NewReverseProxy(http.DefaultTransport, "auto", nil, runtime.Logger,
		internalproxy.WithMiddlewareManager(manager))
	handler := runtime.auth.Protect(runtime.proxy)

	mapping := &proto.ProxyMapping{
		Id: "middleware-revision-service", AccountId: targetAccessAccountID, Domain: targetAccessDomain,
		Path: []*proto.PathMapping{{
			Path: "/", Target: oldBackend.URL,
			Options: &proto.PathTargetOptions{
				AgentNetwork:   true,
				DirectUpstream: true,
				Middlewares: []*proto.MiddlewareConfig{{
					Id:         guardrail.ID,
					Slot:       proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_REQUEST,
					Enabled:    true,
					ConfigJson: []byte(`{"provider_allowlists":{"provider-1":["allowed-model"]}}`),
				}},
			},
		}},
	}
	applyTargetAccessMapping(t, runtime, mapping)
	initial := targetAccessRequestTo(handler, "/v1/chat/completions", "192.0.2.1:1234", nil)
	require.Equal(t, http.StatusForbidden, initial.Code,
		"the original guardrail must reject a request with no known model")
	require.Empty(t, oldUpstream.snapshot(), "the original policy must prevent upstream forwarding")

	// Hold the request at the auth/proxy boundary so updateMapping runs after
	// authorization has pinned the route but before its middleware is selected.
	captureAuthorizedRequest := func() *http.Request {
		var pinned *http.Request
		capture := runtime.auth.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pinned = r
			w.WriteHeader(http.StatusNoContent)
		}))
		response := targetAccessRequestTo(capture, "/v1/chat/completions", "192.0.2.1:1234", nil)
		require.Equal(t, http.StatusNoContent, response.Code, "auth must pass the resolved request to the proxy")
		require.NotNil(t, pinned, "the request must be captured after auth target resolution")
		return pinned
	}
	staleRequest := captureAuthorizedRequest()
	oldChain := manager.ChainFor(mapping.GetId(), "/")
	require.NotNil(t, oldChain, "updateMapping must install the original guardrail chain")

	replacement := protobuf.Clone(mapping).(*proto.ProxyMapping)
	replacement.Path[0].Target = newBackend.URL
	replacement.Path[0].Options.Middlewares[0].ConfigJson = []byte(`{}`)
	applyTargetAccessMapping(t, runtime, replacement)
	newChain := manager.ChainFor(mapping.GetId(), "/")
	require.NotNil(t, newChain, "updateMapping must install the replacement guardrail chain")
	require.NotSame(t, oldChain, newChain, "a policy update must replace the middleware chain")

	staleResponse := httptest.NewRecorder()
	runtime.proxy.ServeHTTP(staleResponse, staleRequest)
	assert.Equal(t, http.StatusServiceUnavailable, staleResponse.Code,
		"a request authorized against the old target must not execute the replacement policy")
	assert.Equal(t, "no-store", staleResponse.Header().Get("Cache-Control"), "stale policy failures must not be cached")
	assert.Empty(t, oldUpstream.snapshot(), "a replacement policy must never authorize the old upstream")
	assert.Empty(t, newUpstream.snapshot(), "a stale request must not forward to the replacement upstream")

	fresh := targetAccessRequestTo(handler, "/v1/chat/completions", "192.0.2.1:1234", nil)
	require.Equal(t, http.StatusOK, fresh.Code, "fresh auth resolution must use the replacement middleware revision")
	require.Len(t, newUpstream.snapshot(), 1, "the replacement target must receive the fresh request")

	// Provider changes rebuild middleware instances without replacing the
	// service mapping, so requests pinned to its current revision stay valid.
	currentRequest := captureAuthorizedRequest()
	manager.InvalidateMiddleware(guardrail.ID)
	refreshedChain := manager.ChainFor(mapping.GetId(), "/")
	require.NotNil(t, refreshedChain, "a live service must retain its chain after provider refresh")
	require.NotSame(t, newChain, refreshedChain, "provider refresh must rebuild the concrete guardrail chain")

	currentResponse := httptest.NewRecorder()
	runtime.proxy.ServeHTTP(currentResponse, currentRequest)
	assert.Equal(t, http.StatusOK, currentResponse.Code, "provider refresh must preserve the current request's revision")
	assert.Len(t, newUpstream.snapshot(), 2, "the current request must reach the replacement target after refresh")

	afterRefresh := targetAccessRequestTo(handler, "/v1/chat/completions", "192.0.2.1:1234", nil)
	assert.Equal(t, http.StatusOK, afterRefresh.Code, "new requests must continue after provider refresh")
	assert.Len(t, newUpstream.snapshot(), 3, "fresh requests must use the rebuilt chain and current target")
	assert.Empty(t, oldUpstream.snapshot(), "no request may reach the retired target")
}
