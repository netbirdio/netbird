package cmd

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/keepalive"
	"github.com/netbirdio/netbird/shared/signal/proto"
	signalserver "github.com/netbirdio/netbird/signal/server"
)

// recordingListener records every accepted connection, so a test can read
// the server socket of a stream.
type recordingListener struct {
	net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func (l *recordingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.conns = append(l.conns, c)
	l.mu.Unlock()
	return c, nil
}

// accepted returns the i-th accepted connection, nil before it exists.
func (l *recordingListener) accepted(i int) net.Conn {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.conns) <= i {
		return nil
	}
	return l.conns[i]
}

// Through the real serveHTTP path an aligned ConnectStream gets the
// confirmed period in its header and the aligned idle on its accepted
// socket. A stock stream on its own connection gets neither.
func TestServeHTTPAlignedStreamKeepAlive(t *testing.T) {
	if _, err := keepalive.Idle(nil); errors.Is(err, errors.ErrUnsupported) {
		t.Skip(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	rec := &recordingListener{Listener: ln}
	t.Cleanup(func() { _ = ln.Close() })

	srv, err := signalserver.NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	defer srv.Stop()
	grpcServer := grpc.NewServer()
	proto.RegisterSignalExchangeServer(grpcServer, srv)
	t.Cleanup(grpcServer.Stop)

	serveHTTP(rec, grpcHandlerFunc(grpcServer, otel.Meter("")))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// connect opens a new connection, reads the idle of the accepted server
	// socket before any stream, then opens a ConnectStream on it. It returns
	// the stream header, the server socket and the idle before the stream.
	connect := func(md metadata.MD, index int) (metadata.MD, net.Conn, time.Duration) {
		conn, err := grpc.NewClient(rec.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		conn.Connect()
		require.Eventually(t, func() bool { return rec.accepted(index) != nil },
			2*time.Second, 10*time.Millisecond, "the serve path must accept connection %d", index)
		serverConn := rec.accepted(index)
		baseline, err := keepalive.Idle(serverConn)
		require.NoError(t, err)
		stream, err := proto.NewSignalExchangeClient(conn).ConnectStream(metadata.NewOutgoingContext(ctx, md))
		require.NoError(t, err)
		header, err := stream.Header()
		require.NoError(t, err, "the server must send its registration header")
		return header, serverConn, baseline
	}

	const alignedKey = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMjU="
	header, alignedConn, _ := connect(metadata.Pairs(proto.HeaderId, alignedKey, alignedhb.MetadataKey, "period=1"), 0)
	assert.Equal(t, []string{"period=30"}, header.Get(alignedhb.MetadataKey), "the header confirms the clamped period")
	assert.Eventually(t, func() bool {
		idle, err := keepalive.Idle(alignedConn)
		return err == nil && idle == 60*time.Second
	}, 2*time.Second, 10*time.Millisecond, "aligned stream: idle twice the clamped period")

	const stockKey = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMjY="
	header, stockConn, stockBaseline := connect(metadata.Pairs(proto.HeaderId, stockKey), 1)
	assert.Empty(t, header.Get(alignedhb.MetadataKey), "a stock stream gets no aligned answer")
	assert.Never(t, func() bool {
		idle, err := keepalive.Idle(stockConn)
		return err != nil || idle != stockBaseline
	}, 200*time.Millisecond, 10*time.Millisecond, "a stock stream must keep the socket idle it had before the stream")
}
