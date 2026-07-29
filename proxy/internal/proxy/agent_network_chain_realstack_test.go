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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	mgmtgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork"
	agentNetworkTypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/proxy/internal/middleware"
	"github.com/netbirdio/netbird/proxy/internal/middleware/bodytap"
	mwbuiltin "github.com/netbirdio/netbird/proxy/internal/middleware/builtin"
	// Side-effect imports register every builtin middleware factory.
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

// TestReverseProxy_AgentNetworkRequest_FullChain is the self-contained Go
// replacement for the bash 50 + 51 legs. It drives a real agent-network
// request through proxy.ReverseProxy.ServeHTTP with the actual middleware
// chain the synthesizer produces, against an in-process management gRPC and a
// httptest fake upstream — no tilt, no docker, no real LLM provider, no
// WireGuard tunnel. The test guarantees:
//
//  1. The reverse proxy's response-leg input construction copies UserGroups
//     onto respInput so llm_limit_record sends a non-empty group_ids field
//     on RecordLLMUsage. This is the exact bug class that motivated the
//     reverseproxy.go fix — its regression would land the request OK but
//     leave consumption at zero, defeating any group-targeted budget rule.
//  2. With settings.RedactPii=true the parsers ship redacted text on both
//     llm.request_prompt_raw and llm.response_completion — proving the
//     end-to-end wiring (synth → proto → spec → parser config) carries the
//     toggle through to runtime emission.
//  3. The full chain (request + response + recorder) runs against a real
//     management stack and the consumption row for the bound group dim
//     increments.
//
// If any of those three guarantees regresses, this single test fails.
func TestReverseProxy_AgentNetworkRequest_FullChain(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sqlite store not supported on Windows")
	}

	const (
		testAccountID = "acct-fullchain-1"
		testAdminUser = "user-admin-1"
		adminGroupID  = "grp-admins"
		providerID    = "prov-openai-test"
		cluster       = "test.proxy.local"
		subdomain     = "fullchain"
	)
	testLogger := log.New()
	testLogger.SetLevel(log.PanicLevel) // keep test output clean

	ctx := context.Background()

	// ---- 1. Fake upstream that returns OpenAI-shaped JSON with PII in the
	// completion. The reverse proxy's chain will redact this when the synth
	// stamps redact_pii=true on the response parser config.
	completion := "Sample record: Alice Johnson alice.johnson@example.com SSN 123-45-6789 phone (202) 555-0147 also Bob 202/555/0108"
	upstreamBody := []byte(`{"id":"x","model":"gpt-5.4","choices":[{"message":{"role":"assistant","content":"` + completion + `"}}],"usage":{"prompt_tokens":12,"completion_tokens":40,"total_tokens":52}}`)
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(upstreamBody)
	}))
	t.Cleanup(upstream.Close)
	upstreamHost := strings.TrimPrefix(upstream.URL, "http://")

	// ---- 2. In-process management gRPC server (bufconn) backed by a real
	// sqlite store + real agentnetwork.Manager. The proxy's middlewares talk
	// to this client.
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

	// ---- 3. Seed account state: settings (redact + capture on), provider
	// whose upstream URL points at our fake server, policy (catch-all-allow
	// over the Admins group → window=0 path), and a generous budget rule
	// targeting Admins so the curl succeeds and we can prove the counter
	// increments on the response leg.
	require.NoError(t, st.SaveAgentNetworkSettings(ctx, &agentNetworkTypes.Settings{
		AccountID:              testAccountID,
		Cluster:                cluster,
		Subdomain:              subdomain,
		EnablePromptCollection: true,
		EnableLogCollection:    true,
		RedactPii:              true,
	}))
	require.NoError(t, st.SaveAgentNetworkProvider(ctx, &agentNetworkTypes.Provider{
		ID:                providerID,
		AccountID:         testAccountID,
		ProviderID:        "openai_api",
		Name:              "openai-fullchain-test",
		UpstreamURL:       upstream.URL, // router rewrites to this
		APIKey:            "sk-test",
		Enabled:           true,
		Models:            []agentNetworkTypes.ProviderModel{{ID: "gpt-5.4"}},
		SessionPrivateKey: "priv",
		SessionPublicKey:  "pub",
	}))
	require.NoError(t, st.SaveAgentNetworkPolicy(ctx, &agentNetworkTypes.Policy{
		ID:                     "ainpol-fullchain",
		AccountID:              testAccountID,
		Name:                   "admins-openai",
		Enabled:                true,
		SourceGroups:           []string{adminGroupID},
		DestinationProviderIDs: []string{providerID},
		// No token / budget caps → effectiveWindowSeconds=0 → exercises the
		// catch-all-allow path that the GC-2 record-on-window=0 fix targets.
	}))
	require.NoError(t, st.SaveAgentNetworkBudgetRule(ctx, &agentNetworkTypes.AccountBudgetRule{
		ID:           "ainbud-admins-fullchain",
		AccountID:    testAccountID,
		Name:         "admins-monthly",
		Enabled:      true,
		TargetGroups: []string{adminGroupID},
		Limits: agentNetworkTypes.PolicyLimits{
			TokenLimit: agentNetworkTypes.PolicyTokenLimit{Enabled: true, GroupCap: 1_000_000, UserCap: 1_000_000, WindowSeconds: 60},
		},
	}))

	// ---- 4. Synth the service. This produces the exact middleware chain
	// configuration the production reconcile path ships to the proxy.
	services, err := agentnetwork.SynthesizeServices(ctx, st, testAccountID)
	require.NoError(t, err)
	require.Len(t, services, 1, "exactly one synth service expected")
	synthSvc := services[0]
	require.NotEmpty(t, synthSvc.Targets, "synth target must exist")

	// ---- 5. Wire the middleware framework — same registry the proxy uses
	// in production, configured with our bufconn-backed management client.
	mwbuiltin.Configure(ctx, t.TempDir(), nil, testLogger, mgmtClient)
	registry := mwbuiltin.DefaultRegistry()
	mwMetrics, err := middleware.NewMetrics(nil)
	require.NoError(t, err)
	mwMgr := middleware.NewManager(0, mwMetrics, testLogger)
	mwMgr.SetResolver(middleware.NewResolver(registry))

	// Convert the synth's rpservice.MiddlewareConfig list into proxy
	// middleware.Spec values. Mirrors the proto→Spec translation server.go
	// does at runtime; kept inline here so the test isn't coupled to the
	// proxy server's private translateMiddlewareConfig helper.
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

	// ---- 6. Build the reverse proxy, with a mapping whose target URL goes
	// straight to the fake upstream (the router middleware rewriting upstream
	// from the synth's noop placeholder isn't needed when we own the mapping
	// in-process — point the target at the fake URL directly so the body
	// arrives at the upstream the synth would have routed to).
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

	// ---- 7. Send a request with the auth-stamped CapturedData (mimicking
	// what the tunnel-peer auth middleware does at the edge of the proxy).
	reqBody := `{"model":"gpt-5.4","client_metadata":{"session_id":"sess-fullchain-1"},"messages":[{"role":"user","content":"contact alice.johnson@example.com SSN 987-65-4321 phone (202)555-0156"}]}`
	req := httptest.NewRequest("POST", "https://"+synthSvc.Domain+"/v1/chat/completions", strings.NewReader(reqBody))
	req.Host = synthSvc.Domain
	req.Header.Set("Content-Type", "application/json")

	cd := proxy.NewCapturedData("test-request-1")
	cd.SetServiceID(nbproxytypes.ServiceID(serviceIDStr))
	cd.SetAccountID(nbproxytypes.AccountID(testAccountID))
	cd.SetUserID(testAdminUser)
	cd.SetUserGroups([]string{adminGroupID})
	cd.SetAuthMethod("tunnel_peer")
	req = req.WithContext(proxy.WithCapturedData(req.Context(), cd))

	w := httptest.NewRecorder()
	rp.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "upstream call must succeed end-to-end; body=%s", w.Body.String())
	assert.GreaterOrEqual(t, upstreamHits.Load(), int64(1), "fake upstream must have been hit")

	// ---- 8. Assertions — the three guarantees this test exists for.

	// 8a. The reverseproxy.go respInput construction carried UserGroups
	// into the response-leg middleware chain, so llm_limit_record sent a
	// non-empty group_ids on RecordLLMUsage. Verifying via the management
	// store directly bypasses the manager's permission gate (which is nil
	// in this test) — we want to confirm the row landed, not who saw it.
	require.Eventually(t, func() bool {
		rows, lerr := st.ListAgentNetworkConsumption(ctx, store.LockingStrengthNone, testAccountID)
		if lerr != nil {
			return false
		}
		for _, r := range rows {
			if r.DimensionKind == agentNetworkTypes.DimensionGroup &&
				r.DimensionID == adminGroupID &&
				r.WindowSeconds == 60 &&
				r.TokensInput+r.TokensOutput > 0 {
				return true
			}
		}
		return false
	}, 5*time.Second, 50*time.Millisecond,
		"Admins group consumption row must increment via the response leg — if this fails the proxy's respInput dropped UserGroups again or the parser/recorder wiring is broken")

	// 8b. Both the captured prompt and the captured completion are
	// redacted — proves the synth threads redact_pii=true into BOTH parser
	// configs and the parsers honour it at emission time.
	md := cd.GetMetadata()
	promptRaw := md["llm.request_prompt_raw"]
	completionMeta := md["llm.response_completion"]

	// 8a-bis. The session id from client_metadata.session_id flows through
	// the request parser into the captured metadata, so the access-log /
	// usage rows can group this request with the rest of its conversation.
	assert.Equal(t, "sess-fullchain-1", md["llm.session_id"],
		"session id must be extracted from client_metadata.session_id and carried through the chain")

	assert.NotEmpty(t, promptRaw, "llm.request_prompt_raw must be present in captured metadata")
	assert.Contains(t, promptRaw, "[REDACTED:", "captured raw prompt must carry redaction markers")
	assert.NotContains(t, promptRaw, "alice.johnson@example.com", "raw email must NOT survive in prompt_raw")
	assert.NotContains(t, promptRaw, "987-65-4321", "raw SSN must NOT survive in prompt_raw")
	assert.NotContains(t, promptRaw, "(202)555-0156", "raw paren-no-space phone must NOT survive in prompt_raw")

	assert.NotEmpty(t, completionMeta, "llm.response_completion must be present in captured metadata")
	assert.Contains(t, completionMeta, "[REDACTED:", "captured completion must carry redaction markers")
	assert.NotContains(t, completionMeta, "alice.johnson@example.com", "raw email must NOT survive in completion")
	assert.NotContains(t, completionMeta, "123-45-6789", "raw SSN must NOT survive in completion")
	assert.NotContains(t, completionMeta, "(202) 555-0147", "raw paren+space phone must NOT survive in completion")
	assert.NotContains(t, completionMeta, "202/555/0108", "raw slash phone must NOT survive in completion")

	_ = upstreamHost // kept for future header-inspection assertions if needed
}
