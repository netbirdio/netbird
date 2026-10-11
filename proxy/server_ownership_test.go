package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/netbirdio/netbird/proxy/internal/auth"
	proxymetrics "github.com/netbirdio/netbird/proxy/internal/metrics"
	"github.com/netbirdio/netbird/proxy/internal/middleware"
	httpproxy "github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/roundtrip"
	nbtcp "github.com/netbirdio/netbird/proxy/internal/tcp"
	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestHTTPForeignOwnerRejectedBeforePublishingState(t *testing.T) {
	for _, authPresent := range []bool{true, false} {
		t.Run(fmt.Sprintf("auth-present=%t", authPresent), func(t *testing.T) {
			srv, l4, original, certManager := setupSharedDomainHTTPAndTLS(t)
			srv.cleanupMappingRoutes(l4)
			if !authPresent {
				srv.auth.RemoveDomain(original.Host)
			}
			// Static-certificate deployments do not have the earlier ACME ownership gate.
			srv.acme = nil
			srv.middlewareRegistry = newTestRegistry(t, map[string]middleware.Slot{"review-test": middleware.SlotOnRequest})
			srv.middlewareManager = middleware.NewManager(0, nil, srv.Logger)
			srv.middlewareManager.SetResolver(middleware.NewResolver(srv.middlewareRegistry))
			t.Cleanup(srv.middlewareManager.InvalidateAll)

			conflict := &proto.ProxyMapping{
				Id: "svc-conflict", AccountId: "another-account", Domain: "SHARED.EXAMPLE.TEST.", Mode: "http",
				Path: []*proto.PathMapping{{Path: "/", Target: "http://127.0.0.1:8080", Options: &proto.PathTargetOptions{
					Middlewares: []*proto.MiddlewareConfig{{Id: "review-test", Enabled: true, Slot: proto.MiddlewareSlot_MIDDLEWARE_SLOT_ON_REQUEST}},
				}}},
			}
			require.ErrorContains(t, srv.setupHTTPMapping(t.Context(), conflict), "owned by")
			if authPresent {
				assert.Equal(t, http.StatusForbidden, protectedDomainStatus(srv.auth, original.Host),
					"a rejected public mapping must not remove the owner's private access policy")
			} else {
				assert.False(t, srv.auth.RemoveDomainForService(original.Host, types.ServiceID(conflict.Id)), "rejected mapping must not publish auth configuration")
			}
			owner, exists := srv.proxy.MappingOwner(original.Host)
			require.True(t, exists, "the original HTTP route must remain")
			assert.Equal(t, original.ID, owner, "HTTP ownership must remain unchanged")
			assert.Nil(t, srv.middlewareManager.ChainFor(conflict.Id, "/"), "rejected services must not publish middleware")
			srv.mainRouter.RemoveRoute(nbtcp.SNIHost(original.Host), original.ID)
			assert.True(t, srv.mainRouter.IsEmpty(), "rejected services must not leave an SNI route")
			assert.Equal(t, 1, certManager.TotalDomains(), "certificate ownership must remain unchanged")
		})
	}
}

func TestHTTPMappingMetricsUseCanonicalHost(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(context.Background())) })
	meter, err := proxymetrics.New(t.Context(), provider.Meter("canonical-mapping-test"))
	require.NoError(t, err)
	logger := quietLifecycleLogger()
	srv := &Server{
		Logger: logger, meter: meter, auth: auth.NewMiddleware(logger, nil, nil),
		proxy:      httpproxy.NewReverseProxy(http.DefaultTransport, "https", nil, logger),
		mainRouter: nbtcp.NewRouter(logger, nil, &net.TCPAddr{Port: 443}),
	}
	mapping := &proto.ProxyMapping{
		Id: "svc", AccountId: "acct", Domain: "App.Example.TEST.:443", Mode: "http",
		Path: []*proto.PathMapping{{Path: "/", Target: "http://127.0.0.1:8080"}},
	}
	require.NoError(t, srv.setupHTTPMapping(t.Context(), mapping))
	mapping.Domain = "app.example.test"
	require.NoError(t, srv.setupHTTPMapping(t.Context(), mapping))
	assertMappingMetric(t, reader, "proxy.domains.count", 1)
	assertMappingMetric(t, reader, "proxy.paths.count", 1)
	srv.cleanupMappingRoutes(mapping)
	assertMappingMetric(t, reader, "proxy.domains.count", 0)
	assertMappingMetric(t, reader, "proxy.paths.count", 0)
}

func assertMappingMetric(t *testing.T, reader *sdkmetric.ManualReader, name string, want int64) {
	t.Helper()
	var metrics metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &metrics))
	for _, scope := range metrics.ScopeMetrics {
		for _, metric := range scope.Metrics {
			if metric.Name != name {
				continue
			}
			sum, ok := metric.Data.(metricdata.Sum[int64])
			require.True(t, ok, "mapping counter must be an integer sum")
			require.Len(t, sum.DataPoints, 1, "mapping counter must have one total")
			assert.Equal(t, want, sum.DataPoints[0].Value, "counter %s must match the installed routes", name)
			return
		}
	}
	t.Fatalf("mapping counter %s was not recorded", name)
}

func TestFailedSnapshotRestoreCleansPartialListeners(t *testing.T) {
	var start uint16
	logger := quietLifecycleLogger()
	meter, err := proxymetrics.New(t.Context(), noop.Meter{})
	require.NoError(t, err)
	var blocker net.Listener
	srv := &Server{
		ctx: t.Context(), Logger: logger, mgmtClient: statusUpdateOnlyClient{}, meter: meter, mainPort: 443,
		mainRouter:  nbtcp.NewRouter(logger, nil, &net.TCPAddr{Port: 443}),
		portRouters: make(map[uint16]*portRouter), svcPorts: make(map[types.ServiceID][]uint16),
		lastMappings: make(map[types.ServiceID]*proto.ProxyMapping),
		addPeer: func(context.Context, types.AccountID, roundtrip.ServiceKey, string, types.ServiceID) error {
			return nil
		},
		removePeer: func(_ context.Context, _ types.AccountID, key roundtrip.ServiceKey) error {
			if key != roundtrip.ServiceIDKey("svc-new") {
				return errors.New("the existing peer must survive a replacement rollback")
			}
			// Hold the second port only after the original listeners were removed,
			// making restoration succeed on the first port and fail on the second.
			var listenErr error
			blocker, listenErr = net.Listen("tcp", fmt.Sprintf(":%d", start+1))
			return listenErr
		},
	}
	old := &proto.ProxyMapping{
		Id: "svc-old", AccountId: "acct", Domain: "app.example.test", Mode: "tcp",
		Path:         []*proto.PathMapping{{Target: "127.0.0.1:8080"}},
		PortMappings: []*proto.ServicePortMapping{{Protocol: "tcp", ListenPortStart: uint32(start), ListenPortEnd: uint32(start + 1), TargetPortStart: 8080, TargetPortEnd: 8081}},
	}
	t.Cleanup(func() {
		srv.cleanupMappingRoutes(old)
		if blocker != nil {
			require.NoError(t, blocker.Close())
		}
		srv.portRouterWg.Wait()
	})
	retryListenerSetup(t, func() error {
		start = reserveTCPPortRange(t, 2)
		old.PortMappings[0].ListenPortStart = uint32(start)
		old.PortMappings[0].ListenPortEnd = uint32(start + 1)
		return srv.setupMappingRoutes(t.Context(), old)
	}, func() { srv.cleanupMappingRoutes(old) })
	srv.storeMapping(old)
	broken := &proto.ProxyMapping{
		Id: "svc-new", AccountId: "acct", Mode: "tcp", ListenPort: int32(start),
		Path: []*proto.PathMapping{{Target: "missing-port"}},
	}
	require.ErrorContains(t, srv.addMapping(t.Context(), broken), "restore superseded service svc-old")
	require.NotNil(t, blocker, "the second port must be occupied during restoration")
	assert.Nil(t, srv.loadMapping("svc-old"), "failed restore must not be cached as live")
	assert.Nil(t, srv.routerForPortExisting(start), "a partially restored listener must be removed")
	srv.portMu.RLock()
	assert.Empty(t, srv.svcPorts["svc-old"], "failed restore must release all tracked ports")
	srv.portMu.RUnlock()
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", start))
	require.NoError(t, err, "a different service must be able to bind the cleaned-up port")
	require.NoError(t, listener.Close())
}
