package ssh

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestHandshake_ContextDeadlineWrapped(t *testing.T) {
	conn := dialSilentServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := Handshake(ctx, conn, conn.RemoteAddr().String(), testClientConfig())
	require.Error(t, err)
	require.True(t, errors.Is(err, context.DeadlineExceeded), "expected context.DeadlineExceeded, got: %v", err)
}

func TestHandshake_ContextCanceledWrapped(t *testing.T) {
	conn := dialSilentServer(t)
	require.NoError(t, conn.Close())

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Handshake(ctx, conn, conn.RemoteAddr().String(), testClientConfig())
	require.Error(t, err)
	require.True(t, errors.Is(err, context.Canceled), "expected context.Canceled, got: %v", err)
}

func TestHandshake_NonContextErrorNotWrapped(t *testing.T) {
	conn := dialSilentServer(t)
	require.NoError(t, conn.Close())

	_, err := Handshake(context.Background(), conn, conn.RemoteAddr().String(), testClientConfig())
	require.Error(t, err)
	require.False(t, errors.Is(err, context.Canceled))
	require.False(t, errors.Is(err, context.DeadlineExceeded))
}

func testClientConfig() *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            "test",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
}

// dialSilentServer returns a client conn to a server that accepts and never
// sends anything, so the SSH handshake blocks until the deadline hits.
func dialSilentServer(t *testing.T) net.Conn {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		c, err := listener.Accept()
		if err != nil {
			return
		}
		t.Cleanup(func() { _ = c.Close() })
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return conn
}
