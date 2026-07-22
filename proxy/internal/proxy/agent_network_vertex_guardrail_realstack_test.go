package proxy_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork"
	agentNetworkTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	mgmtgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/bodytap"
	mwbuiltin "github.com/netbirdio/netbird/proxy/internal/middleware/builtin"
	_ "github.com/netbirdio/netbird/proxy/internal/middleware/builtin/cost_meter"
	_ "github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_guardrail"
	_ "github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_identity_inject"
	_ "github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_limit_check"
	_ "github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_limit_record"
	_ "github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_request_parser"
	_ "github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_response_parser"
	_ "github.com/netbirdio/netbird/proxy/internal/middleware/builtin/llm_router"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
	nbproxytypes "github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/proto"

	log "github.com/sirupsen/logrus"
)

// TestReverseProxy_VertexGuardrail_ModelAllowlist drives Anthropic-on-Vertex
// requests (model in the URL path, not the body) through the full synthesized
// middleware chain against an in-process management stack and a fake upstream.
// With a Sonnet-only guardrail, Opus must be denied (model_blocked) before the
// upstream and Sonnet must reach it. Two provider shapes exercise different
// code: "catch_all" (no models → only the guardrail can block Opus) and
// "versioned_models" (raw "@version" ids → the router must normalize to route
// Sonnet while the guardrail still blocks Opus).
func TestReverseProxy_VertexGuardrail_ModelAllowlist(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sqlite store not supported on Windows")
	}

	cases := []struct {
		name           string
		providerModels []agentNetworkTypes.ProviderModel
	}{
		{name: "catch_all", providerModels: nil},
		{name: "versioned_models", providerModels: []agentNetworkTypes.ProviderModel{
			{ID: "claude-sonnet-4-5@20250929"},
			{ID: "claude-opus-4-6@20250514"},
		}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			runVertexGuardrailCase(t, tc.providerModels)
		})
	}
}

func runVertexGuardrailCase(t *testing.T, providerModels []agentNetworkTypes.ProviderModel) {
	t.Helper()

	const (
		testAccountID = "acct-vertex-guard-1"
		testAdminUser = "user-admin-1"
		adminGroupID  = "grp-admins"
		providerID    = "prov-vertex-test"
		guardrailID   = "ainguard-sonnet-only"
		cluster       = "test.proxy.local"
		subdomain     = "vertexguard"
	)
	testLogger := log.New()
	testLogger.SetLevel(log.PanicLevel)

	ctx := context.Background()

	// Fake Vertex upstream: a hit on the disallowed model means a guardrail miss.
	var upstreamHits atomic.Int64
	upstreamBody := []byte(`{"id":"msg_x","type":"message","role":"assistant","model":"claude","content":[{"type":"text","text":"pong"}],"usage":{"input_tokens":5,"output_tokens":2}}`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(upstreamBody)
	}))
	t.Cleanup(upstream.Close)

	// In-process management gRPC (bufconn) over a real sqlite store + manager.
	st, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "real sqlite test store must come up")
	t.Cleanup(cleanup)

	anMgr := agentnetwork.NewManager(st, nil, nil, nil)
	server := &mgmtgrpc.ProxyServiceServer{}
	server.SetAgentNetworkLimitsService(anMgr)

	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	proto.RegisterProxyServiceServer(srv, server)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	mgmtClient := proto.NewProxyServiceClient(conn)

	require.NoError(t, st.SaveAgentNetworkSettings(ctx, &agentNetworkTypes.Settings{
		AccountID: testAccountID,
		Cluster:   cluster,
		Subdomain: subdomain,
	}))
	require.NoError(t, st.SaveAgentNetworkProvider(ctx, &agentNetworkTypes.Provider{
		ID:          providerID,
		AccountID:   testAccountID,
		ProviderID:  "vertex_ai_api",
		Name:        "vertex-guard-test",
		UpstreamURL: upstream.URL,
		// A static bearer (not "keyfile::…") so the router injects a static auth
		// header instead of minting a GCP token, which needs network egress and
		// would deny before the guardrail runs, masking the decision under test.
		APIKey:            "static-vertex-token",
		Enabled:           true,
		Models:            providerModels,
		SessionPrivateKey: "priv",
		SessionPublicKey:  "pub",
	}))
	// Guardrail allowlisting ONLY Sonnet.
	require.NoError(t, st.SaveAgentNetworkGuardrail(ctx, &agentNetworkTypes.Guardrail{
		ID:        guardrailID,
		AccountID: testAccountID,
		Name:      "sonnet-only",
		Checks: agentNetworkTypes.GuardrailChecks{
			ModelAllowlist: agentNetworkTypes.GuardrailModelAllowlist{
				Enabled: true,
				Models:  []string{"claude-sonnet-4-5"},
			},
		},
	}))
	require.NoError(t, st.SaveAgentNetworkPolicy(ctx, &agentNetworkTypes.Policy{
		ID:                     "ainpol-vertex-guard",
		AccountID:              testAccountID,
		Name:                   "admins-vertex",
		Enabled:                true,
		SourceGroups:           []string{adminGroupID},
		DestinationProviderIDs: []string{providerID},
		GuardrailIDs:           []string{guardrailID},
	}))

	services, err := agentnetwork.SynthesizeServices(ctx, st, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1, "exactly one synth service expected")
	synthSvc := services[0]
	require.NotEmpty(t, synthSvc.Targets, "synth target must exist")

	mwbuiltin.Configure(ctx, t.TempDir(), nil, testLogger, mgmtClient)
	registry := mwbuiltin.DefaultRegistry()
	mwMetrics, err := middleware.NewMetrics(nil)
	require.NoError(t, err)
	mwMgr := middleware.NewManager(0, mwMetrics, testLogger)
	mwMgr.SetResolver(middleware.NewResolver(registry))

	specs := make([]middleware.Spec, 0, len(synthSvc.Targets[0].Options.Middlewares))
	for _, mw := range synthSvc.Targets[0].Options.Middlewares {
		var slot middleware.Slot
		switch mw.Slot {
		case rpservice.MiddlewareSlotOnRequest:
			slot = middleware.SlotOnRequest
		case rpservice.MiddlewareSlotOnResponse:
			slot = middleware.SlotOnResponse
		case rpservice.MiddlewareSlotTerminal:
			slot = middleware.SlotTerminal
		default:
			t.Fatalf("unknown middleware slot %q on %s", mw.Slot, mw.ID)
		}
		specs = append(specs, middleware.Spec{
			ID:        mw.ID,
			Slot:      slot,
			Enabled:   mw.Enabled,
			FailMode:  middleware.FailOpen,
			Timeout:   middleware.DefaultTimeout,
			RawConfig: append([]byte(nil), mw.ConfigJSON...),
			CanMutate: mw.CanMutate,
		})
	}

	serviceIDStr := synthSvc.ID
	require.NoError(t, mwMgr.Rebuild(serviceIDStr, []middleware.PathTargetBinding{{
		ServiceID: serviceIDStr,
		PathID:    "/",
		Specs:     specs,
	}}))

	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	rp := proxy.NewReverseProxy(http.DefaultTransport, "auto", nil, testLogger, proxy.WithMiddlewareManager(mwMgr))
	rp.AddMapping(proxy.Mapping{
		ID:        nbproxytypes.ServiceID(serviceIDStr),
		AccountID: nbproxytypes.AccountID(testAccountID),
		Host:      synthSvc.Domain,
		Paths: map[string]*proxy.PathTarget{
			"/": {
				URL:            upstreamURL,
				DirectUpstream: true,
				AgentNetwork:   true,
				Middlewares:    specs,
				CaptureConfig: &bodytap.Config{
					MaxRequestBytes:  1 << 20,
					MaxResponseBytes: 1 << 20,
					ContentTypes:     []string{"application/json", "text/event-stream"},
				},
			},
		},
	})

	// No "model" field — the model lives in the URL path, as Vertex clients send.
	const vertexBody = `{"anthropic_version":"vertex-2023-10-16","max_tokens":64,"messages":[{"role":"user","content":"Reply with exactly: pong"}]}`

	send := func(t *testing.T, model string) (int, int64, string) {
		t.Helper()
		before := upstreamHits.Load()
		path := "/v1/projects/corp-gcp-it-all-claude/locations/global/publishers/anthropic/models/" + model + ":rawPredict"
		req := httptest.NewRequest("POST", "https://"+synthSvc.Domain+path, strings.NewReader(vertexBody))
		req.Host = synthSvc.Domain
		req.Header.Set("Content-Type", "application/json")

		cd := proxy.NewCapturedData("req-" + model)
		cd.SetServiceID(nbproxytypes.ServiceID(serviceIDStr))
		cd.SetAccountID(nbproxytypes.AccountID(testAccountID))
		cd.SetUserID(testAdminUser)
		cd.SetUserGroups([]string{adminGroupID})
		cd.SetAuthMethod("tunnel_peer")
		req = req.WithContext(proxy.WithCapturedData(req.Context(), cd))

		w := httptest.NewRecorder()
		rp.ServeHTTP(w, req)
		return w.Code, upstreamHits.Load() - before, w.Body.String()
	}

	// Opus must be denied by the guardrail (model_blocked, not the router's
	// model_not_routable) before reaching the upstream — the customer-reported bug.
	t.Run("opus_denied_by_guardrail", func(t *testing.T) {
		code, hits, body := send(t, "claude-opus-4-6")
		assert.Equal(t, http.StatusForbidden, code, "Opus must be denied under a Sonnet-only allowlist; body=%s", body)
		assert.Contains(t, body, "llm_policy.model_blocked", "denial must come from the guardrail allowlist, not routing; body=%s", body)
		assert.Equal(t, int64(0), hits, "a denied request must never reach the Vertex upstream")
	})

	// The allowed model (Sonnet) passes the guardrail and reaches the upstream.
	t.Run("sonnet_allowed", func(t *testing.T) {
		code, hits, body := send(t, "claude-sonnet-4-5")
		assert.Equal(t, http.StatusOK, code, "Sonnet is allowlisted and must be served; body=%s", body)
		assert.Equal(t, int64(1), hits, "the allowed request must reach the Vertex upstream exactly once")
	})
}
