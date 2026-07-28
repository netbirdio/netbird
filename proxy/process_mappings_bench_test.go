package proxy

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/proxy/internal/auth"
	"github.com/netbirdio/netbird/proxy/internal/conntrack"
	"github.com/netbirdio/netbird/proxy/internal/crowdsec"
	proxymetrics "github.com/netbirdio/netbird/proxy/internal/metrics"
	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/roundtrip"
	nbtcp "github.com/netbirdio/netbird/proxy/internal/tcp"
	"github.com/netbirdio/netbird/proxy/internal/types"
	udprelay "github.com/netbirdio/netbird/proxy/internal/udp"
	"github.com/netbirdio/netbird/shared/management/proto"

	"go.opentelemetry.io/otel/metric/noop"
)

// latencyMockClient simulates realistic gRPC latency for management calls.
type latencyMockClient struct {
	proto.ProxyServiceClient
	createPeerDelay   time.Duration
	statusUpdateDelay time.Duration
}

func (m *latencyMockClient) SendStatusUpdate(ctx context.Context, _ *proto.SendStatusUpdateRequest, _ ...grpc.CallOption) (*proto.SendStatusUpdateResponse, error) {
	if m.statusUpdateDelay > 0 {
		select {
		case <-time.After(m.statusUpdateDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return &proto.SendStatusUpdateResponse{}, nil
}

func (m *latencyMockClient) CreateProxyPeer(ctx context.Context, _ *proto.CreateProxyPeerRequest, _ ...grpc.CallOption) (*proto.CreateProxyPeerResponse, error) {
	if m.createPeerDelay > 0 {
		select {
		case <-time.After(m.createPeerDelay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return &proto.CreateProxyPeerResponse{Success: true}, nil
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func benchServerWithLatency(b *testing.B, createPeerDelay, statusDelay time.Duration) *Server {
	b.Helper()
	logger := log.New()
	logger.SetLevel(log.FatalLevel)
	logger.SetOutput(&discardWriter{})

	meter, err := proxymetrics.New(context.Background(), noop.Meter{})
	if err != nil {
		b.Fatal(err)
	}

	mgmtClient := &latencyMockClient{
		createPeerDelay:   createPeerDelay,
		statusUpdateDelay: statusDelay,
	}

	nb := roundtrip.NewNetBird(b.Context(), "bench-proxy", "bench.test",
		roundtrip.ClientConfig{MgmtAddr: "http://bench.test:9999"},
		logger, nil, mgmtClient)

	mainRouter := nbtcp.NewRouter(logger, func(accountID types.AccountID) (types.DialContextFunc, error) {
		return (&net.Dialer{}).DialContext, nil
	}, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443})

	return &Server{
		Logger:           logger,
		mgmtClient:       mgmtClient,
		netbird:          nb,
		proxy:            proxy.NewReverseProxy(nil, "auto", nil, logger),
		auth:             auth.NewMiddleware(logger, nil, nil),
		mainRouter:       mainRouter,
		mainPort:         443,
		meter:            meter,
		hijackTracker:    conntrack.HijackTracker{},
		crowdsecRegistry: crowdsec.NewRegistry("", "", log.NewEntry(logger)),
		crowdsecServices: make(map[types.ServiceID]bool),
		lastMappings:     make(map[types.ServiceID]*proto.ProxyMapping),
		portRouters:      make(map[uint16]*portRouter),
		svcPorts:         make(map[types.ServiceID][]uint16),
		udpRelays:        make(map[types.ServiceID]*udprelay.Relay),
	}
}

// generateHTTPMappings creates N HTTP-mode mappings with the given update type.
// All belong to a single account to share the embedded client.
func generateHTTPMappings(n int, updateType proto.ProxyMappingUpdateType) []*proto.ProxyMapping {
	mappings := make([]*proto.ProxyMapping, n)
	for i := range n {
		mappings[i] = &proto.ProxyMapping{
			Type:      updateType,
			Id:        fmt.Sprintf("svc-%d", i),
			AccountId: "account-1",
			Domain:    fmt.Sprintf("svc-%d.bench.example.com", i),
			Mode:      "http",
			Path: []*proto.PathMapping{
				{
					Path:   "/",
					Target: fmt.Sprintf("http://10.0.%d.%d:8080", (i/256)%256, i%256),
				},
			},
			Auth: &proto.Authentication{},
		}
	}
	return mappings
}

// generateMultiAccountHTTPMappings creates N HTTP-mode CREATED mappings spread
// across the given number of accounts. This stresses the AddPeer new-account
// path which calls CreateProxyPeer + embed.New per unique account.
func generateMultiAccountHTTPMappings(n, accounts int) []*proto.ProxyMapping {
	mappings := make([]*proto.ProxyMapping, n)
	for i := range n {
		mappings[i] = &proto.ProxyMapping{
			Type:      proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED,
			Id:        fmt.Sprintf("svc-%d", i),
			AccountId: fmt.Sprintf("account-%d", i%accounts),
			Domain:    fmt.Sprintf("svc-%d.bench.example.com", i),
			Mode:      "http",
			Path: []*proto.PathMapping{
				{
					Path:   "/",
					Target: fmt.Sprintf("http://10.0.%d.%d:8080", (i/256)%256, i%256),
				},
			},
			Auth: &proto.Authentication{},
		}
	}
	return mappings
}

// generateMixedMappings creates mappings with a realistic distribution:
// 70% HTTP create, 15% modify existing, 10% TLS on main port, 5% remove.
// All use a single account to avoid embed.New dialing.
func generateMixedMappings(n int) []*proto.ProxyMapping {
	mappings := make([]*proto.ProxyMapping, n)
	for i := range n {
		var m *proto.ProxyMapping
		switch {
		case i%20 < 14: // 70% HTTP create
			m = &proto.ProxyMapping{
				Type:      proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED,
				Id:        fmt.Sprintf("svc-http-%d", i),
				AccountId: "account-1",
				Domain:    fmt.Sprintf("svc-%d.bench.example.com", i),
				Mode:      "http",
				Path: []*proto.PathMapping{
					{Path: "/", Target: fmt.Sprintf("http://10.0.%d.%d:8080", (i/256)%256, i%256)},
					{Path: "/api", Target: fmt.Sprintf("http://10.0.%d.%d:8081", (i/256)%256, i%256)},
				},
				Auth: &proto.Authentication{},
			}
		case i%20 < 17: // 15% modify
			m = &proto.ProxyMapping{
				Type:      proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED,
				Id:        fmt.Sprintf("svc-http-%d", i%100),
				AccountId: "account-1",
				Domain:    fmt.Sprintf("svc-%d.bench.example.com", i%100),
				Mode:      "http",
				Path: []*proto.PathMapping{
					{Path: "/", Target: fmt.Sprintf("http://10.1.%d.%d:8080", (i/256)%256, i%256)},
				},
				Auth: &proto.Authentication{},
			}
		case i%20 < 19: // 10% TLS passthrough on main port
			m = &proto.ProxyMapping{
				Type:       proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED,
				Id:         fmt.Sprintf("svc-tls-%d", i),
				AccountId:  "account-1",
				Domain:     fmt.Sprintf("tls-%d.bench.example.com", i),
				Mode:       "tls",
				ListenPort: 443,
				Path: []*proto.PathMapping{
					{Path: "/", Target: fmt.Sprintf("10.2.%d.%d:443", (i/256)%256, i%256)},
				},
			}
		default: // 5% remove
			m = &proto.ProxyMapping{
				Type:      proto.ProxyMappingUpdateType_UPDATE_TYPE_REMOVED,
				Id:        fmt.Sprintf("svc-http-%d", i%50),
				AccountId: "account-1",
				Domain:    fmt.Sprintf("svc-%d.bench.example.com", i%50),
				Mode:      "http",
			}
		}
		mappings[i] = m
	}
	return mappings
}

const (
	createPeerLatency   = 100 * time.Millisecond
	statusUpdateLatency = 50 * time.Millisecond
)

// BenchmarkProcessMappings_HTTPCreate_SingleAccount benchmarks the initial sync
// scenario: N HTTP mappings all on a single account. Only the first mapping
// triggers CreateProxyPeer (100ms gRPC). The rest just register with the
// existing client. This is the "best case" production path.
func BenchmarkProcessMappings_HTTPCreate_SingleAccount(b *testing.B) {
	for _, n := range []int{100, 1000, 5000} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			mappings := generateHTTPMappings(n, proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED)
			for range b.N {
				s := benchServerWithLatency(b, createPeerLatency, statusUpdateLatency)
				s.processMappings(b.Context(), mappings)
			}
		})
	}
}

// BenchmarkProcessMappings_HTTPCreate_MultiAccount benchmarks the worst-case
// initial sync: every mapping belongs to a different account, so each one
// triggers a full CreateProxyPeer gRPC round-trip (100ms) + embed.New.
// With 500 accounts this serializes to ~50s of blocking I/O.
func BenchmarkProcessMappings_HTTPCreate_MultiAccount(b *testing.B) {
	for _, tc := range []struct {
		mappings int
		accounts int
	}{
		{100, 10},
		{100, 50},
		{1000, 50},
		{1000, 200},
		{3000, 500},
	} {
		b.Run(fmt.Sprintf("mappings=%d/accounts=%d", tc.mappings, tc.accounts), func(b *testing.B) {
			mappings := generateMultiAccountHTTPMappings(tc.mappings, tc.accounts)
			for range b.N {
				s := benchServerWithLatency(b, createPeerLatency, statusUpdateLatency)
				s.processMappings(b.Context(), mappings)
			}
		})
	}
}

// BenchmarkProcessMappings_Mixed benchmarks a realistic mixed workload
// of creates, modifies, TLS, and removes with production-like latency.
// TLS mappings call SendStatusUpdate (50ms each), serialized.
func BenchmarkProcessMappings_Mixed(b *testing.B) {
	for _, n := range []int{100, 1000, 5000} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			mappings := generateMixedMappings(n)
			for range b.N {
				s := benchServerWithLatency(b, createPeerLatency, statusUpdateLatency)
				creates := generateHTTPMappings(100, proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED)
				s.processMappings(b.Context(), creates)
				s.processMappings(b.Context(), mappings)
			}
		})
	}
}

// BenchmarkProcessMappings_ModifyOnly benchmarks bulk modification of
// already-registered mappings (no new peers needed, no gRPC).
func BenchmarkProcessMappings_ModifyOnly(b *testing.B) {
	for _, n := range []int{100, 1000, 5000} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			creates := generateHTTPMappings(n, proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED)
			modifies := generateHTTPMappings(n, proto.ProxyMappingUpdateType_UPDATE_TYPE_MODIFIED)
			for range b.N {
				s := benchServerWithLatency(b, createPeerLatency, statusUpdateLatency)
				s.processMappings(b.Context(), creates)
				s.processMappings(b.Context(), modifies)
			}
		})
	}
}

// BenchmarkProcessMappings_NoLatency measures pure CPU/allocation overhead
// with zero I/O latency for profiling purposes.
func BenchmarkProcessMappings_NoLatency(b *testing.B) {
	for _, n := range []int{1000, 5000} {
		b.Run(fmt.Sprintf("n=%d", n), func(b *testing.B) {
			mappings := generateHTTPMappings(n, proto.ProxyMappingUpdateType_UPDATE_TYPE_CREATED)
			for range b.N {
				s := benchServerWithLatency(b, 0, 0)
				s.processMappings(b.Context(), mappings)
			}
		})
	}
}
