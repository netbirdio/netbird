package keepalive

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c" //nolint:staticcheck // the servers serve plaintext gRPC through h2c, so the test does too
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// tcpPair returns both ends of a loopback TCP connection.
func tcpPair(t *testing.T) (client, server *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	s, ok := <-accepted
	require.True(t, ok, "accept must succeed")
	t.Cleanup(func() { _ = s.Close() })
	return c.(*net.TCPConn), s.(*net.TCPConn)
}

type wrapped struct {
	net.Conn
}

func (w wrapped) NetConn() net.Conn { return w.Conn }

func TestTCPConnUnwraps(t *testing.T) {
	c, _ := tcpPair(t)

	got, ok := TCPConn(c)
	assert.True(t, ok, "plain TCP connection")
	assert.Same(t, c, got)

	got, ok = TCPConn(tls.Client(wrapped{c}, &tls.Config{}))
	assert.True(t, ok, "TLS over a wrapper")
	assert.Same(t, c, got)

	p1, p2 := net.Pipe()
	defer func() { _ = p1.Close() }()
	defer func() { _ = p2.Close() }()
	_, ok = TCPConn(p1)
	assert.False(t, ok, "a pipe has no TCP socket")
	_, ok = TCPConn(wrapped{})
	assert.False(t, ok, "a wrapper without a connection")
	_, ok = TCPConn(nil)
	assert.False(t, ok, "nil")
}

func skipWithoutIdle(t *testing.T) {
	t.Helper()
	if _, err := Idle(nil); errors.Is(err, errors.ErrUnsupported) {
		t.Skip(err)
	}
}

func TestAlignedConfigAndUserTimeout(t *testing.T) {
	cfg := AlignedConfig(60 * time.Second)
	assert.True(t, cfg.Enable)
	assert.Equal(t, 2*time.Minute, cfg.Idle)
	assert.Equal(t, 15*time.Second, cfg.Interval)
	assert.Equal(t, 3, cfg.Count)
	assert.Equal(t, 150*time.Second, UserTimeout(60*time.Second), "2T + 30 s")
	assert.Equal(t, 90*time.Second, UserTimeout(30*time.Second))
}

func TestSetAligned(t *testing.T) {
	skipWithoutIdle(t)
	c, s := tcpPair(t)

	require.NoError(t, SetAligned(wrapped{c}, time.Minute))
	idle, err := Idle(c)
	require.NoError(t, err)
	assert.Equal(t, 2*time.Minute, idle, "aligned idle at a 60 s period")

	// Setting the same connection again changes nothing.
	require.NoError(t, SetAligned(c, time.Minute))
	idle, err = Idle(c)
	require.NoError(t, err)
	assert.Equal(t, 2*time.Minute, idle)

	require.NoError(t, SetAligned(s, 90*time.Second))
	idle, err = Idle(s)
	require.NoError(t, err)
	assert.Equal(t, 3*time.Minute, idle, "server end at a 90 s period")

	assert.Error(t, SetAligned(c, 0), "a zero period must be refused")
	assert.Error(t, SetAligned(c, -time.Second), "a negative period must be refused")

	p1, p2 := net.Pipe()
	defer func() { _ = p1.Close() }()
	defer func() { _ = p2.Close() }()
	assert.ErrorIs(t, SetAligned(p1, time.Minute), ErrNotTCP)
}

func TestSetAlignedLeavesUserTimeout(t *testing.T) {
	c, _ := tcpPair(t)
	if _, err := userTimeout(c); errors.Is(err, errors.ErrUnsupported) {
		t.Skip(err)
	}

	require.NoError(t, SetAligned(c, time.Minute))
	got, err := userTimeout(c)
	require.NoError(t, err)
	assert.Zero(t, got, "clients use SetAligned, the user timeout is for servers only")
}

// TestSetAlignedStreamThroughGRPC serves gRPC through an http.Server with
// ConnContext, as Management and Signal do, and checks that a stream handler
// reaches and tunes its own connection.
func TestSetAlignedStreamThroughGRPC(t *testing.T) {
	skipWithoutIdle(t)

	streamConn := make(chan net.Conn, 1)
	gs := grpc.NewServer(grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
		if err := SetAlignedStream(stream.Context(), time.Minute); err != nil {
			return err
		}
		conn, _ := ConnFromContext(stream.Context())
		streamConn <- conn
		return nil
	}))
	hs := &http.Server{
		//nolint:staticcheck // same h2c handler as the Management and Signal plaintext listeners
		Handler:           h2c.NewHandler(gs, &http2.Server{}),
		ConnContext:       ConnContext,
		ReadHeaderTimeout: 5 * time.Second,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() {
		_ = hs.Close()
		gs.Stop()
	})

	cc, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := cc.NewStream(ctx, &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}, "/test.Aligned/Stream")
	require.NoError(t, err)
	require.NoError(t, stream.CloseSend())

	var conn net.Conn
	select {
	case conn = <-streamConn:
	case <-ctx.Done():
		t.Fatal("stream handler did not get its connection")
	}
	idle, err := Idle(conn)
	require.NoError(t, err)
	assert.Equal(t, 2*time.Minute, idle, "aligned idle on the server end of the stream")

	tc, ok := TCPConn(conn)
	require.True(t, ok)
	if got, err := userTimeout(tc); !errors.Is(err, errors.ErrUnsupported) {
		require.NoError(t, err)
		assert.Equal(t, 150*time.Second, got, "TCP_USER_TIMEOUT at a 60 s period")
	}
}

func TestSetAlignedStreamWithoutConn(t *testing.T) {
	assert.ErrorIs(t, SetAlignedStream(context.Background(), time.Minute), ErrNoConn,
		"no ConnContext wired: stock behaviour, reported not panicked")
	_, ok := ConnFromContext(nil) //nolint:staticcheck // a nil context must not panic
	assert.False(t, ok)

	p1, p2 := net.Pipe()
	defer func() { _ = p1.Close() }()
	defer func() { _ = p2.Close() }()
	assert.ErrorIs(t, SetAlignedStream(ConnContext(context.Background(), p1), time.Minute), ErrNotTCP)
}
