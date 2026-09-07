package server

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/realip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"

	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
)

const realIPProbeMethod = "/netbird.test.RealIPProbe/Probe"

// realIPProbe records the real IP the middleware derived for each call.
type realIPProbe struct {
	got chan string
}

func (p *realIPProbe) probe(ctx context.Context) {
	addr, _ := realip.FromContext(ctx)
	p.got <- addr.String()
}

func startProbeServer(t *testing.T, cfg nbconfig.ReverseProxy) (*grpc.ClientConn, *realIPProbe) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	probe := &realIPProbe{got: make(chan string, 1)}
	srv := grpc.NewServer(grpc.ChainUnaryInterceptor(realip.UnaryServerInterceptorOpts(realIPOptions(cfg)...)))
	srv.RegisterService(&grpc.ServiceDesc{
		ServiceName: "netbird.test.RealIPProbe",
		HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{{
			MethodName: "Probe",
			Handler: func(_ any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
				req := new(emptypb.Empty)
				if err := dec(req); err != nil {
					return nil, err
				}
				handler := func(ctx context.Context, _ any) (any, error) {
					probe.probe(ctx)
					return &emptypb.Empty{}, nil
				}
				if interceptor == nil {
					return handler(ctx, req)
				}
				return interceptor(ctx, req, &grpc.UnaryServerInfo{FullMethod: realIPProbeMethod}, handler)
			},
		}},
	}, probe)

	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return conn, probe
}

func callWithMetadata(t *testing.T, conn *grpc.ClientConn, probe *realIPProbe, kv ...string) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, kv...)
	require.NoError(t, conn.Invoke(ctx, realIPProbeMethod, &emptypb.Empty{}, &emptypb.Empty{}))

	select {
	case got := <-probe.got:
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for probe")
		return ""
	}
}

func TestRealIPDefaultIgnoresClientForwardedHeaders(t *testing.T) {
	conn, probe := startProbeServer(t, nbconfig.ReverseProxy{})

	got := callWithMetadata(t, conn, probe,
		realip.XForwardedFor, "203.0.113.44",
		realip.XRealIp, "203.0.113.44",
	)
	assert.Equal(t, "127.0.0.1", got, "empty TrustedPeers must fall back to the transport peer address")
}

func TestRealIPUntrustedPeerIgnoresForwardedHeaders(t *testing.T) {
	conn, probe := startProbeServer(t, nbconfig.ReverseProxy{
		TrustedPeers: []netip.Prefix{netip.MustParsePrefix("10.9.8.7/32")},
	})

	got := callWithMetadata(t, conn, probe,
		realip.XForwardedFor, "203.0.113.44",
		realip.XRealIp, "203.0.113.44",
	)
	assert.Equal(t, "127.0.0.1", got, "forwarded headers must be ignored for peers outside TrustedPeers")
}

func TestRealIPTrustedPeerHonoursForwardedHeaders(t *testing.T) {
	conn, probe := startProbeServer(t, nbconfig.ReverseProxy{
		TrustedPeers: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
	})

	got := callWithMetadata(t, conn, probe,
		realip.XForwardedFor, "203.0.113.44",
		realip.XRealIp, "203.0.113.44",
	)
	assert.Equal(t, "203.0.113.44", got, "a trusted proxy must be able to forward the real client IP")
}

func TestRealIPIgnoresXRealIPWhenProxyCountIsSet(t *testing.T) {
	conn, probe := startProbeServer(t, nbconfig.ReverseProxy{
		TrustedPeers:            []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		TrustedHTTPProxiesCount: 1,
	})

	got := callWithMetadata(t, conn, probe, realip.XRealIp, "203.0.113.44")
	assert.Equal(t, "127.0.0.1", got, "X-Real-IP must never be trusted, fall back to the transport peer")
}
