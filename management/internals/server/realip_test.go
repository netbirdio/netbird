package server

import (
	"context"
	"io"
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

const (
	realIPProbeMethod       = "/netbird.test.RealIPProbe/Probe"
	realIPProbeStreamMethod = "/netbird.test.RealIPProbe/ProbeStream"
)

// realIPProbe records the real IP the middleware derived for each call.
type realIPProbe struct {
	got chan string
}

func (p *realIPProbe) record(ctx context.Context) {
	addr, _ := realip.FromContext(ctx)
	p.got <- addr.String()
}

func (p *realIPProbe) wait(t *testing.T) string {
	t.Helper()

	select {
	case got := <-p.got:
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for probe")
		return ""
	}
}

func startProbeServer(t *testing.T, cfg nbconfig.ReverseProxy) (*grpc.ClientConn, *realIPProbe) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	probe := &realIPProbe{got: make(chan string, 1)}
	opts := realIPOptions(cfg)
	srv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(realip.UnaryServerInterceptorOpts(opts...)),
		grpc.ChainStreamInterceptor(realip.StreamServerInterceptorOpts(opts...)),
	)
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
					probe.record(ctx)
					return &emptypb.Empty{}, nil
				}
				if interceptor == nil {
					return handler(ctx, req)
				}
				return interceptor(ctx, req, &grpc.UnaryServerInfo{FullMethod: realIPProbeMethod}, handler)
			},
		}},
		Streams: []grpc.StreamDesc{{
			StreamName:    "ProbeStream",
			ServerStreams: true,
			Handler: func(_ any, stream grpc.ServerStream) error {
				probe.record(stream.Context())
				return nil
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

func callUnary(t *testing.T, conn *grpc.ClientConn, probe *realIPProbe, kv ...string) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, kv...)
	require.NoError(t, conn.Invoke(ctx, realIPProbeMethod, &emptypb.Empty{}, &emptypb.Empty{}))

	return probe.wait(t)
}

func callStream(t *testing.T, conn *grpc.ClientConn, probe *realIPProbe, kv ...string) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, kv...)
	desc := &grpc.StreamDesc{StreamName: "ProbeStream", ServerStreams: true}
	stream, err := conn.NewStream(ctx, desc, realIPProbeStreamMethod)
	require.NoError(t, err)
	require.NoError(t, stream.CloseSend())
	require.ErrorIs(t, stream.RecvMsg(&emptypb.Empty{}), io.EOF)

	return probe.wait(t)
}

func assertRealIP(t *testing.T, cfg nbconfig.ReverseProxy, want string, kv ...string) {
	t.Helper()

	conn, probe := startProbeServer(t, cfg)
	t.Run("unary", func(t *testing.T) {
		assert.Equal(t, want, callUnary(t, conn, probe, kv...))
	})
	t.Run("stream", func(t *testing.T) {
		assert.Equal(t, want, callStream(t, conn, probe, kv...))
	})
}

func TestRealIPDefaultIgnoresClientForwardedHeaders(t *testing.T) {
	assertRealIP(t, nbconfig.ReverseProxy{}, "127.0.0.1",
		realip.XForwardedFor, "203.0.113.44",
		realip.XRealIp, "203.0.113.44",
	)
}

func TestRealIPUntrustedPeerIgnoresForwardedHeaders(t *testing.T) {
	cfg := nbconfig.ReverseProxy{TrustedPeers: []netip.Prefix{netip.MustParsePrefix("10.9.8.7/32")}}

	assertRealIP(t, cfg, "127.0.0.1",
		realip.XForwardedFor, "203.0.113.44",
		realip.XRealIp, "203.0.113.44",
	)
}

func TestRealIPTrustedPeerHonoursForwardedHeaders(t *testing.T) {
	cfg := nbconfig.ReverseProxy{TrustedPeers: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}

	assertRealIP(t, cfg, "203.0.113.44",
		realip.XForwardedFor, "203.0.113.44",
		realip.XRealIp, "203.0.113.44",
	)
}

func TestRealIPIgnoresXRealIPWhenProxyCountIsSet(t *testing.T) {
	cfg := nbconfig.ReverseProxy{
		TrustedPeers:            []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
		TrustedHTTPProxiesCount: 1,
	}

	assertRealIP(t, cfg, "127.0.0.1", realip.XRealIp, "203.0.113.44")
}
