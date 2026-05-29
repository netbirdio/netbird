package owner

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials"
)

func TestUnixTransportCredentials_ServerHandshake(t *testing.T) {
	creds := NewUnixTransportCredentials()
	if creds == nil {
		t.Skip("unix transport credentials not supported on this platform")
	}

	sockPath := filepath.Join(t.TempDir(), "test.sock")

	ln, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	done := make(chan struct{})
	var serverConn net.Conn
	var serverAuth credentials.AuthInfo
	var serverErr error

	go func() {
		defer close(done)
		raw, err := ln.Accept()
		if err != nil {
			serverErr = err
			return
		}
		serverConn, serverAuth, serverErr = creds.ServerHandshake(raw)
	}()

	client, err := net.Dial("unix", sockPath)
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })

	<-done
	require.NoError(t, serverErr)
	require.NotNil(t, serverConn)
	t.Cleanup(func() { serverConn.Close() })

	authInfo, ok := serverAuth.(UnixAuthInfo)
	require.True(t, ok, "expected UnixAuthInfo, got %T", serverAuth)
	assert.Equal(t, UID(os.Getuid()), authInfo.UID, "UID should match current user")
}

func TestUnixTransportCredentials_ServerHandshake_NonUnixConn(t *testing.T) {
	creds := NewUnixTransportCredentials()
	if creds == nil {
		t.Skip("unix transport credentials not supported on this platform")
	}

	// Use a TCP connection, which is not *net.UnixConn.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	done := make(chan struct{})
	var handshakeErr error

	go func() {
		defer close(done)
		raw, err := ln.Accept()
		if err != nil {
			handshakeErr = err
			return
		}
		defer raw.Close()
		_, _, handshakeErr = creds.ServerHandshake(raw)
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })

	<-done
	require.Error(t, handshakeErr, "ServerHandshake must fail for non-Unix connections")
}

func TestUnixTransportCredentials_Info(t *testing.T) {
	creds := NewUnixTransportCredentials()
	if creds == nil {
		t.Skip("unix transport credentials not supported on this platform")
	}

	info := creds.Info()
	assert.Equal(t, "unix_peercred", info.SecurityProtocol)
}

func TestUnixTransportCredentials_Clone(t *testing.T) {
	creds := NewUnixTransportCredentials()
	if creds == nil {
		t.Skip("unix transport credentials not supported on this platform")
	}

	cloned := creds.Clone()
	require.NotNil(t, cloned)
	assert.Equal(t, creds.Info(), cloned.Info())
}
