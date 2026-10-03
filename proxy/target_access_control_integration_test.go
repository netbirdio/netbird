package proxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	nbproxy "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/proxy/internal/auth"
	proxymetrics "github.com/netbirdio/netbird/proxy/internal/metrics"
	internalproxy "github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/roundtrip"
	nbtcp "github.com/netbirdio/netbird/proxy/internal/tcp"
	proxytypes "github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/hash/argon2id"
	"github.com/netbirdio/netbird/shared/management/proto"
)

const (
	targetAccessAccountID = "test-account-1"
	targetAccessCluster   = "test.proxy.io"
	targetAccessDomain    = "target-access.test.proxy.io"
	targetAccessHeader    = "X-Test-Key"
	targetAccessSecret    = "valid-secret"
)

type targetAccessRequest struct {
	path    string
	headers http.Header
}

type targetAccessUpstream struct {
	mu       sync.Mutex
	requests []targetAccessRequest
}

func (u *targetAccessUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	u.requests = append(u.requests, targetAccessRequest{
		path:    r.URL.Path,
		headers: r.Header.Clone(),
	})
	u.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (u *targetAccessUpstream) snapshot() []targetAccessRequest {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]targetAccessRequest(nil), u.requests...)
}

func targetAccessService(t *testing.T, upstreamURL string) *service.Service {
	t.Helper()

	u, err := url.Parse(upstreamURL)
	require.NoError(t, err)
	host, portText, err := net.SplitHostPort(u.Host)
	require.NoError(t, err)
	port, err := strconv.ParseUint(portText, 10, 16)
	require.NoError(t, err)

	headerHash, err := argon2id.Hash(targetAccessSecret)
	require.NoError(t, err)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	newTarget := func(path string, action service.TargetAccessAction) *service.Target {
		return &service.Target{
			Path:         strPtr(path),
			Host:         host,
			Port:         uint16(port),
			Protocol:     u.Scheme,
			TargetId:     "target-access-upstream",
			TargetType:   service.TargetTypeCluster,
			Enabled:      true,
			AccessAction: action,
			Options: service.TargetOptions{
				DirectUpstream: true,
			},
		}
	}

	return &service.Service{
		ID:                "target-access-service",
		AccountID:         targetAccessAccountID,
		Name:              "Target Access Control",
		Domain:            targetAccessDomain,
		ProxyCluster:      targetAccessCluster,
		Enabled:           true,
		SessionPrivateKey: base64.StdEncoding.EncodeToString(privateKey),
		SessionPublicKey:  base64.StdEncoding.EncodeToString(publicKey),
		Targets: []*service.Target{
			newTarget("/", service.TargetAccessActionInherit),
			newTarget("/public", service.TargetAccessActionBypass),
			newTarget("/blocked", service.TargetAccessActionBlock),
		},
		Auth: service.AuthConfig{HeaderAuths: []*service.HeaderAuthConfig{{
			Enabled: true,
			Header:  targetAccessHeader,
			Value:   headerHash,
		}}},
		Restrictions: service.AccessRestrictions{
			BlockedCIDRs: []string{"203.0.113.0/24"},
		},
	}
}

func privateServiceCapabilities() *proto.ProxyCapabilities {
	supported := true
	return &proto.ProxyCapabilities{
		SupportsPrivateService: &supported,
	}
}

func targetAccessMappingStream(t *testing.T, setup *integrationTestSetup, proxyID string, caps *proto.ProxyCapabilities) proto.ProxyService_GetMappingUpdateClient {
	t.Helper()

	conn, err := grpc.NewClient(setup.grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	stream, err := proto.NewProxyServiceClient(conn).GetMappingUpdate(ctx, &proto.GetMappingUpdateRequest{
		ProxyId:      proxyID,
		Version:      "target-access-test",
		Address:      targetAccessCluster,
		Capabilities: caps,
	})
	require.NoError(t, err)
	return stream
}

func receiveTargetAccessSnapshot(t *testing.T, stream proto.ProxyService_GetMappingUpdateClient) map[string]*proto.ProxyMapping {
	t.Helper()

	mappings := make(map[string]*proto.ProxyMapping)
	for {
		msg, err := stream.Recv()
		require.NoError(t, err)
		for _, mapping := range msg.GetMapping() {
			mappings[mapping.GetId()] = mapping
		}
		if msg.GetInitialSyncComplete() {
			return mappings
		}
	}
}

func receiveTargetAccessUpdate(t *testing.T, stream proto.ProxyService_GetMappingUpdateClient, serviceID string) *proto.ProxyMapping {
	t.Helper()

	for {
		msg, err := stream.Recv()
		require.NoError(t, err)
		for _, mapping := range msg.GetMapping() {
			if mapping.GetId() == serviceID {
				return mapping
			}
		}
	}
}

func newTargetAccessRuntime(t *testing.T) (*Server, http.Handler) {
	t.Helper()

	logger := quietLifecycleLogger()
	meter, err := proxymetrics.New(t.Context(), noop.Meter{})
	require.NoError(t, err)

	reverseProxy := internalproxy.NewReverseProxy(http.DefaultTransport, "auto", nil, logger)
	authMiddleware := auth.NewMiddleware(logger, nil, nil)
	srv := &Server{
		ctx:              t.Context(),
		Logger:           logger,
		proxy:            reverseProxy,
		auth:             authMiddleware,
		meter:            meter,
		mainRouter:       nbtcp.NewRouter(logger, nil, &net.TCPAddr{}),
		portRouters:      make(map[uint16]*portRouter),
		svcPorts:         make(map[proxytypes.ServiceID][]uint16),
		lastMappings:     make(map[proxytypes.ServiceID]*proto.ProxyMapping),
		crowdsecServices: make(map[proxytypes.ServiceID]bool),
		removePeer: func(context.Context, proxytypes.AccountID, roundtrip.ServiceKey) error {
			return nil
		},
	}

	return srv, authMiddleware.Protect(reverseProxy)
}

func applyTargetAccessMapping(t *testing.T, srv *Server, mapping *proto.ProxyMapping) {
	t.Helper()
	require.NoError(t, srv.updateMapping(t.Context(), mapping))
	srv.storeMapping(mapping)
}

func targetAccessRequestTo(handler http.Handler, path, remoteAddr string, headers http.Header) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://"+targetAccessDomain+path, nil)
	req.Host = targetAccessDomain
	req.RemoteAddr = remoteAddr
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

func TestModifyHTTPMappingFromEmptyPathsRegistersRoute(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Test-Upstream", "reached")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)

	runtime, handler := newTargetAccessRuntime(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	router := nbtcp.NewRouter(runtime.Logger, func(proxytypes.AccountID) (proxytypes.DialContextFunc, error) {
		return func(context.Context, string, string) (net.Conn, error) {
			return nil, net.ErrClosed
		}, nil
	}, listener.Addr())
	router.SetFallback(nbtcp.Route{
		Type:      nbtcp.RouteTCP,
		AccountID: "fallback-account",
		ServiceID: "fallback-service",
		Target:    "unreachable.test:443",
	})
	runtime.mainRouter = router

	httpServer := &http.Server{
		Handler:           handler,
		TLSConfig:         selfSignedTLSConfig(t),
		ReadHeaderTimeout: time.Second,
	}
	t.Cleanup(func() { _ = httpServer.Close() })
	go func() { _ = httpServer.ServeTLS(router.HTTPListener(), "", "") }()
	go feedRouterFromListener(t.Context(), listener, router, runtime.Logger, proxytypes.AccountID(targetAccessAccountID))

	previous := &proto.ProxyMapping{
		Id:        "empty-to-routable",
		AccountId: targetAccessAccountID,
		Domain:    targetAccessDomain,
	}
	runtime.storeMapping(previous)
	replacement := &proto.ProxyMapping{
		Id:        previous.GetId(),
		AccountId: previous.GetAccountId(),
		Domain:    previous.GetDomain(),
		Path: []*proto.PathMapping{{
			Path:   "/",
			Target: upstream.URL,
		}},
	}
	require.NoError(t, runtime.modifyMapping(t.Context(), replacement))

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Get("https://" + targetAccessDomain + "/ready")
	require.NoError(t, err, "first target must register the domain with the SNI router")
	t.Cleanup(func() { _ = response.Body.Close() })
	assert.Equal(t, http.StatusNoContent, response.StatusCode)
	assert.Equal(t, "reached", response.Header.Get("X-Test-Upstream"))
}

func TestIntegration_TargetAccessControl_ManagementToUpstream(t *testing.T) {
	setup := setupIntegrationTest(t)
	t.Cleanup(setup.cleanup)

	upstreamRecorder := &targetAccessUpstream{}
	upstream := httptest.NewServer(upstreamRecorder)
	t.Cleanup(upstream.Close)

	svc := targetAccessService(t, upstream.URL)
	require.NoError(t, setup.store.CreateService(t.Context(), svc))

	stream := targetAccessMappingStream(t, setup, "target-access-proxy", nil)
	snapshot := receiveTargetAccessSnapshot(t, stream)
	mapping := snapshot[svc.ID]
	require.NotNil(t, mapping, "proxy must receive the target-access service")

	actions := make(map[string]proto.TargetAccessAction)
	for _, pathMapping := range mapping.GetPath() {
		actions[pathMapping.GetPath()] = pathMapping.GetAccessAction()
	}
	assert.Equal(t, proto.TargetAccessAction_TARGET_ACCESS_ACTION_INHERIT, actions["/"])
	assert.Equal(t, proto.TargetAccessAction_TARGET_ACCESS_ACTION_BYPASS, actions["/public"])
	assert.Equal(t, proto.TargetAccessAction_TARGET_ACCESS_ACTION_BLOCK, actions["/blocked"])

	runtime, handler := newTargetAccessRuntime(t)
	applyTargetAccessMapping(t, runtime, mapping)

	before := len(upstreamRecorder.snapshot())
	res := targetAccessRequestTo(handler, "/private", "198.51.100.10:12000", nil)
	assert.Equal(t, http.StatusUnauthorized, res.Code, "inherit must retain service authentication")
	assert.Len(t, upstreamRecorder.snapshot(), before, "unauthenticated inherited request must not reach upstream")

	validHeader := http.Header{targetAccessHeader: []string{targetAccessSecret}}
	res = targetAccessRequestTo(handler, "/private", "198.51.100.10:12000", validHeader)
	assert.Equal(t, http.StatusOK, res.Code, "valid service authentication must pass an inherited target")
	inheritedRequests := upstreamRecorder.snapshot()
	require.Len(t, inheritedRequests, before+1)
	assert.Empty(t, inheritedRequests[len(inheritedRequests)-1].headers.Get(targetAccessHeader),
		"proxy authentication credential must not be forwarded upstream")

	bypassHeaders := http.Header{
		targetAccessHeader: []string{"spoofed-auth"},
		"X-NetBird-User":   []string{"spoofed@example.com"},
		"X-NetBird-Groups": []string{"administrators"},
	}
	res = targetAccessRequestTo(handler, "/public/ready", "198.51.100.10:12000", bypassHeaders)
	assert.Equal(t, http.StatusOK, res.Code, "bypass target must reach upstream without authenticating")
	bypassRequests := upstreamRecorder.snapshot()
	require.Len(t, bypassRequests, before+2)
	bypassed := bypassRequests[len(bypassRequests)-1]
	assert.Equal(t, "/ready", bypassed.path, "routing must retain the existing literal-prefix rewrite")
	assert.Empty(t, bypassed.headers.Get(targetAccessHeader), "configured auth header must be stripped on bypass")
	assert.Empty(t, bypassed.headers.Get("X-NetBird-User"), "bypass must not permit spoofed identity")
	assert.Empty(t, bypassed.headers.Get("X-NetBird-Groups"), "bypass must not permit spoofed groups")

	before = len(bypassRequests)
	res = targetAccessRequestTo(handler, "/blocked/secret", "198.51.100.10:12000", validHeader)
	assert.Equal(t, http.StatusForbidden, res.Code, "block must win even when service authentication is valid")
	assert.Len(t, upstreamRecorder.snapshot(), before, "blocked request must not reach upstream")

	res = targetAccessRequestTo(handler, "/public/ready", "203.0.113.8:12000", nil)
	assert.Equal(t, http.StatusForbidden, res.Code, "connection restrictions must run before bypass")
	assert.Len(t, upstreamRecorder.snapshot(), before, "restricted bypass request must not reach upstream")

	for _, target := range svc.Targets {
		switch *target.Path {
		case "/public":
			target.AccessAction = service.TargetAccessActionBlock
		case "/blocked":
			target.AccessAction = service.TargetAccessActionBypass
		}
	}
	require.NoError(t, setup.store.UpdateService(t.Context(), svc))
	persisted, err := setup.store.GetServiceByID(t.Context(), store.LockingStrengthNone, targetAccessAccountID, svc.ID)
	require.NoError(t, err)
	update := persisted.ToProtoMapping(service.Update, "", nbproxy.OIDCValidationConfig{})
	setup.proxyService.SendServiceUpdate(&proto.GetMappingUpdateResponse{Mapping: []*proto.ProxyMapping{update}})
	receivedUpdate := receiveTargetAccessUpdate(t, stream, svc.ID)
	applyTargetAccessMapping(t, runtime, receivedUpdate)

	res = targetAccessRequestTo(handler, "/public/ready", "198.51.100.10:12000", validHeader)
	assert.Equal(t, http.StatusForbidden, res.Code, "modified action must replace bypass with block")
	assert.Len(t, upstreamRecorder.snapshot(), before, "newly blocked request must not reach upstream")

	res = targetAccessRequestTo(handler, "/blocked/ready", "198.51.100.10:12000", nil)
	assert.Equal(t, http.StatusOK, res.Code, "modified action must replace block with bypass")
	assert.Len(t, upstreamRecorder.snapshot(), before+1, "newly bypassed request must reach upstream")

	require.NoError(t, setup.store.DeleteService(t.Context(), targetAccessAccountID, svc.ID))
	removed := persisted.ToProtoMapping(service.Delete, "", nbproxy.OIDCValidationConfig{})
	setup.proxyService.SendServiceUpdate(&proto.GetMappingUpdateResponse{Mapping: []*proto.ProxyMapping{removed}})
	receivedRemoval := receiveTargetAccessUpdate(t, stream, svc.ID)
	runtime.removeMapping(t.Context(), receivedRemoval)

	res = targetAccessRequestTo(handler, "/blocked/ready", "198.51.100.10:12000", nil)
	assert.Equal(t, http.StatusNotFound, res.Code, "removed mapping must no longer route")
	assert.Len(t, upstreamRecorder.snapshot(), before+1, "request after removal must not reach upstream")
}

func TestIntegration_TargetAccessControl_PrivateServiceRejectsBypass(t *testing.T) {
	setup := setupIntegrationTest(t)
	t.Cleanup(setup.cleanup)

	upstreamRecorder := &targetAccessUpstream{}
	upstream := httptest.NewServer(upstreamRecorder)
	t.Cleanup(upstream.Close)

	svc := targetAccessService(t, upstream.URL)
	svc.ID = "target-access-private"
	svc.Domain = "target-access-private.test.proxy.io"
	svc.Private = true
	svc.Targets = svc.Targets[1:2]
	require.NoError(t, setup.store.CreateService(t.Context(), svc))

	stream := targetAccessMappingStream(t, setup, "target-access-private", privateServiceCapabilities())
	mapping := receiveTargetAccessSnapshot(t, stream)[svc.ID]
	require.NotNil(t, mapping, "proxy supporting private services must receive private target-access mapping")

	runtime, handler := newTargetAccessRuntime(t)
	err := runtime.updateMapping(t.Context(), mapping)
	require.Error(t, err, "private service with a bypass target must be rejected")

	req := httptest.NewRequest(http.MethodGet, "http://"+svc.Domain+"/public/ready", nil)
	req.Host = svc.Domain
	req.RemoteAddr = "100.64.0.20:12000"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusNotFound, recorder.Code, "rejected private mapping must not be published")
	assert.Empty(t, upstreamRecorder.snapshot(), "rejected private mapping must not reach upstream")
}
