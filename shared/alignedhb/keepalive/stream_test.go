package keepalive

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c" //nolint:staticcheck // the servers use h2c for plain gRPC
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// connHealth is a health service that records whether a call could reach its
// connection through the context.
type connHealth struct {
	*health.Server
	found chan bool
}

func (h *connHealth) Check(ctx context.Context, req *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	c, ok := ConnFromContext(ctx)
	if ok {
		_, ok = TCPConn(c)
	}
	h.found <- ok
	return h.Server.Check(ctx, req)
}

func newConnHealthServer() (*grpc.Server, *connHealth) {
	gs := grpc.NewServer()
	h := &connHealth{Server: health.NewServer(), found: make(chan bool, 1)}
	healthpb.RegisterHealthServer(gs, h)
	return gs, h
}

func checkFound(t *testing.T, conn *grpc.ClientConn, h *connHealth) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	require.NoError(t, err)
	assert.True(t, <-h.found, "the gRPC handler must reach the TCP connection through its context")
}

// The servers run gRPC through net/http, as h2c and over TLS. Both must hand
// the accepted connection to the stream context.
func TestConnContextReachesGRPCHandler(t *testing.T) {
	t.Run("h2c", func(t *testing.T) {
		gs, h := newConnHealthServer()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		//nolint:staticcheck // h2c also handles the HTTP/1 Upgrade mechanism, which http.Server's UnencryptedHTTP2 does not
		srv := &http.Server{Handler: h2c.NewHandler(gs, &http2.Server{}), ConnContext: ConnContext}
		go func() { _ = srv.Serve(ln) }()
		t.Cleanup(func() { _ = srv.Close() })

		conn, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		checkFound(t, conn, h)
	})

	t.Run("tls", func(t *testing.T) {
		gs, h := newConnHealthServer()
		srv := httptest.NewUnstartedServer(gs)
		srv.EnableHTTP2 = true
		srv.Config.ConnContext = ConnContext
		srv.StartTLS()
		t.Cleanup(srv.Close)

		creds := credentials.NewTLS(&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test server certificate
		conn, err := grpc.NewClient(srv.Listener.Addr().String(), grpc.WithTransportCredentials(creds))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		checkFound(t, conn, h)
	})
}

func TestStreamSetAlignedAndRestore(t *testing.T) {
	skipWithoutIdle(t)
	_, s := tcpPair(t)
	ctx := ConnContext(context.Background(), s)

	st := ForStream(ctx)
	require.NotNil(t, st)
	st.SetAligned(time.Minute)
	idle, err := Idle(s)
	require.NoError(t, err)
	assert.Equal(t, 2*time.Minute, idle, "aligned stream")

	st.Restore()
	idle, err = Idle(s)
	require.NoError(t, err)
	assert.Equal(t, 15*time.Second, idle, "restored to stock when the stream ends")

	st.SetAligned(time.Minute)
	idle, err = Idle(s)
	require.NoError(t, err)
	assert.Equal(t, 15*time.Second, idle, "an ended stream must not change the connection again")
}

func TestStreamWithoutConn(t *testing.T) {
	st := ForStream(context.Background())
	assert.Nil(t, st, "no connection in the context")
	assert.NotPanics(t, func() {
		st.SetAligned(time.Minute)
		st.Restore()
	})
}

// A client reopens its stream on the same connection, so the old stream can end
// after the new one is aligned. The keepalive belongs to the connection: it stays
// aligned until the last aligned stream on it ends.
func TestStreamsShareConnection(t *testing.T) {
	skipWithoutIdle(t)
	_, s := tcpPair(t)
	ctx := ConnContext(context.Background(), s)
	idle := func() time.Duration {
		t.Helper()
		d, err := Idle(s)
		require.NoError(t, err)
		return d
	}

	old, cur := ForStream(ctx), ForStream(ctx)
	old.SetAligned(time.Minute)
	cur.SetAligned(time.Minute)
	old.Restore()
	assert.Equal(t, 2*time.Minute, idle(), "the new stream keeps the connection aligned")

	cur.Restore()
	assert.Equal(t, 15*time.Second, idle(), "stock once the last aligned stream ends")
}

// Two aligned streams with different periods share one connection, as the
// Management and Signal streams of the combined server do. The longest period
// sets the idle, so neither stream gets a probe between two of its heartbeats.
func TestStreamsShareConnectionLongestPeriod(t *testing.T) {
	skipWithoutIdle(t)
	_, s := tcpPair(t)
	ctx := ConnContext(context.Background(), s)
	idle := func() time.Duration {
		t.Helper()
		d, err := Idle(s)
		require.NoError(t, err)
		return d
	}

	short, long := ForStream(ctx), ForStream(ctx)
	short.SetAligned(time.Minute)
	long.SetAligned(2 * time.Minute)
	assert.Equal(t, 4*time.Minute, idle(), "the longest period sets the idle")

	long.Restore()
	assert.Equal(t, 2*time.Minute, idle(), "the remaining stream sets the idle")

	long.SetAligned(2 * time.Minute)
	assert.Equal(t, 2*time.Minute, idle(), "an ended stream changes nothing")

	short.Restore()
	assert.Equal(t, 15*time.Second, idle(), "stock once the last aligned stream ends")
	assert.Empty(t, conns.byConn, "no state kept for a connection without aligned streams")
}
