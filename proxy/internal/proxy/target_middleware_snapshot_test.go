package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
	guardrail "github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_guardrail"
)

func TestReverseProxy_PinnedTargetFailsClosedAcrossMiddlewareRevisions(t *testing.T) {
	restrictiveGuardrail := []middleware.Spec{{
		ID:        guardrail.ID,
		Slot:      middleware.SlotOnRequest,
		Enabled:   true,
		RawConfig: []byte(`{"provider_allowlists":{"provider-1":["allowed-model"]}}`),
	}}
	unrestrictedGuardrail := []middleware.Spec{{
		ID:        guardrail.ID,
		Slot:      middleware.SlotOnRequest,
		Enabled:   true,
		RawConfig: []byte(`{}`),
	}}

	tests := []struct {
		name           string
		oldMiddlewares []middleware.Spec
		newMiddlewares []middleware.Spec
		oldStatus      int
	}{
		{
			name:           "replacement policy cannot authorize old target",
			oldMiddlewares: restrictiveGuardrail,
			newMiddlewares: unrestrictedGuardrail,
			oldStatus:      http.StatusForbidden,
		},
		{
			name:           "new policy cannot run on old no-policy target",
			newMiddlewares: unrestrictedGuardrail,
			oldStatus:      http.StatusNoContent,
		},
		{
			name:           "removed policy cannot disappear from old target",
			oldMiddlewares: unrestrictedGuardrail,
			oldStatus:      http.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := middleware.NewRegistry()
			require.NoError(t, registry.Register(guardrail.Factory{}))
			manager := middleware.NewManager(0, nil, nil)
			manager.SetResolver(middleware.NewResolver(registry))

			oldTarget := &PathTarget{
				URL:          mustTargetURL(t, "http://old-agent-backend.internal"),
				AgentNetwork: true,
				Middlewares:  tt.oldMiddlewares,
			}
			oldMapping := resolverMapping(map[string]*PathTarget{"/": oldTarget})
			oldRevision := rebuildMiddlewareSnapshot(t, manager, &oldMapping)
			oldResolver, err := NewTargetResolver(oldMapping)
			require.NoError(t, err)

			// Auth resolves and pins the old route and middleware revision before
			// the replacement snapshot is installed.
			req := httptest.NewRequest(http.MethodPost, "http://example.com/v1/chat/completions", nil)
			oldPinnedReq, _, err := oldResolver.ResolveRequest(req)
			require.NoError(t, err)

			var upstreamHosts []string
			rp := NewReverseProxy(resolverRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				upstreamHosts = append(upstreamHosts, req.URL.Host)
				return &http.Response{
					StatusCode: http.StatusNoContent,
					Header:     make(http.Header),
					Body:       http.NoBody,
				}, nil
			}), "auto", nil, nil, WithMiddlewareManager(manager))

			before := httptest.NewRecorder()
			rp.ServeHTTP(before, oldPinnedReq.Clone(oldPinnedReq.Context()))
			require.Equal(t, tt.oldStatus, before.Code, "the original snapshot must work before replacement")
			if tt.oldStatus == http.StatusNoContent {
				require.Equal(t, []string{"old-agent-backend.internal"}, upstreamHosts)
			} else {
				require.Empty(t, upstreamHosts)
			}
			upstreamHosts = nil

			newTarget := &PathTarget{
				URL:          mustTargetURL(t, "http://new-agent-backend.internal"),
				AgentNetwork: true,
				Middlewares:  tt.newMiddlewares,
			}
			newMapping := resolverMapping(map[string]*PathTarget{"/": newTarget})
			newRevision := rebuildMiddlewareSnapshot(t, manager, &newMapping)
			require.NotEqual(t, oldRevision, newRevision)

			stale := httptest.NewRecorder()
			rp.ServeHTTP(stale, oldPinnedReq)

			assert.Equal(t, http.StatusServiceUnavailable, stale.Code,
				"a pinned target must not use a replacement middleware revision")
			assert.Equal(t, "no-store", stale.Header().Get("Cache-Control"))
			assert.Empty(t, upstreamHosts,
				"a mixed target/policy generation must never reach an upstream")

			// A request resolved from the replacement route snapshot is coherent
			// with the replacement chain and reaches only the new backend.
			newResolver, err := NewTargetResolver(newMapping)
			require.NoError(t, err)
			freshReq, _, err := newResolver.ResolveRequest(
				httptest.NewRequest(http.MethodPost, "http://example.com/v1/chat/completions", nil),
			)
			require.NoError(t, err)

			fresh := httptest.NewRecorder()
			rp.ServeHTTP(fresh, freshReq)

			assert.Equal(t, http.StatusNoContent, fresh.Code)
			assert.Equal(t, []string{"new-agent-backend.internal"}, upstreamHosts)
		})
	}
}

func rebuildMiddlewareSnapshot(t *testing.T, manager *middleware.Manager, mapping *Mapping) middleware.Revision {
	t.Helper()
	bindings := make([]middleware.PathTargetBinding, 0, len(mapping.Paths))
	for path, target := range mapping.Paths {
		if target == nil || len(target.Middlewares) == 0 {
			continue
		}
		bindings = append(bindings, middleware.PathTargetBinding{
			ServiceID: string(mapping.ID),
			PathID:    path,
			Specs:     target.Middlewares,
		})
	}
	revision, err := manager.RebuildSnapshot(string(mapping.ID), bindings)
	require.NoError(t, err)
	require.NotZero(t, revision)
	mapping.MiddlewareRevision = revision
	return revision
}
