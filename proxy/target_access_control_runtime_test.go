package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"

	"github.com/netbirdio/netbird/proxy/internal/auth"
	proxymetrics "github.com/netbirdio/netbird/proxy/internal/metrics"
	internalproxy "github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/roundtrip"
	nbtcp "github.com/netbirdio/netbird/proxy/internal/tcp"
	proxytypes "github.com/netbirdio/netbird/proxy/internal/types"
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
