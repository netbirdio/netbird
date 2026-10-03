package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/relay/server/listener/quic"
	"github.com/netbirdio/netbird/shared/relay/auth/allow"
)

func TestServer_ShutdownBeforeListen(t *testing.T) {
	addr := freeAddress(t)
	srv := newTestServer(t, addr)
	require.NoError(t, srv.Shutdown(context.Background()))

	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Listen(ListenerConfig{Address: addr})
	}()

	assert.NoError(t, waitForListenToReturn(t, errChan))
	assert.Empty(t, srv.ListenerProtocols(), "a shut down server must not register listeners")
	requireAddressFree(t, addr)
}

func TestServer_ShutdownStopsListen(t *testing.T) {
	addr := freeAddress(t)
	srv := newTestServer(t, addr)

	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Listen(ListenerConfig{Address: addr})
	}()

	waitForListeners(t, srv, errChan)

	require.NoError(t, srv.Shutdown(context.Background()))
	assert.NoError(t, waitForListenToReturn(t, errChan))
	requireAddressFree(t, addr)
}

func TestServer_ConcurrentListenAndShutdown(t *testing.T) {
	tlsCfg := testTLSConfig(t)
	for round := 0; round < 20; round++ {
		t.Run(fmt.Sprintf("round-%d", round), func(t *testing.T) {
			addr := freeAddress(t)
			srv := newTestServer(t, addr)

			start := make(chan struct{})
			listenErr := make(chan error, 1)
			shutdownErr := make(chan error, 1)
			go func() {
				<-start
				listenErr <- srv.Listen(ListenerConfig{Address: addr, TLSConfig: tlsCfg})
			}()
			go func() {
				<-start
				shutdownErr <- srv.Shutdown(context.Background())
			}()
			close(start)

			// Either side may take the lock first: Listen then returns without binding,
			// or Shutdown stops its accept loops. Listen must return in both cases.
			assert.NoError(t, waitForListenToReturn(t, listenErr))
			assert.NoError(t, <-shutdownErr)
			assert.Empty(t, srv.ListenerProtocols(), "no listener may stay registered after shutdown")
			requireAddressFree(t, addr)
		})
	}
}

func TestServer_ListenReturnsBindError(t *testing.T) {
	blocker, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = blocker.Close() })
	addr := blocker.Addr().String()
	srv := newTestServer(t, addr)

	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Listen(ListenerConfig{Address: addr})
	}()

	assert.Error(t, waitForListenToReturn(t, errChan), "Listen must return the bind error instead of serving")
	assert.Empty(t, srv.ListenerProtocols(), "a failed Listen must not register listeners")

	require.NoError(t, blocker.Close())
	requireAddressFree(t, addr)
}

func TestServer_ListenRollsBackOnBindError(t *testing.T) {
	addr := freeAddress(t)
	blocker, err := net.ListenPacket("udp", addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = blocker.Close() })
	srv := newTestServer(t, addr)
	tlsCfg := testTLSConfig(t)

	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Listen(ListenerConfig{Address: addr, TLSConfig: tlsCfg})
	}()

	err = waitForListenToReturn(t, errChan)
	require.Error(t, err, "Listen must fail when the QUIC port is taken")
	assert.ErrorContains(t, err, string(quic.Proto)+" listener", "the QUIC listener must be the one that failed to bind")
	assert.Empty(t, srv.ListenerProtocols(), "a failed Listen must not register listeners")

	// The WS listener binds first, so a free TCP port proves the rollback closed it.
	ln, err := net.Listen("tcp", addr)
	require.NoError(t, err, "the WS socket must be released after the QUIC bind failure")
	require.NoError(t, ln.Close())
}

func newTestServer(t *testing.T, addr string) *Server {
	t.Helper()
	srv, err := NewServer(Config{
		ExposedAddress: "rel://" + addr,
		AuthValidator:  &allow.Auth{},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, srv.Shutdown(context.Background()))
	})
	return srv
}

// The server binds TCP and UDP on the same port, so a port is only picked when
// both are free. The probes are closed before Listen binds, which leaves a small
// window for another process to take the port; waitForListeners then reports the
// bind error instead of a timeout.
func freeAddress(t *testing.T) string {
	t.Helper()
	for attempt := 0; attempt < 10; attempt++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		addr := ln.Addr().String()
		require.NoError(t, ln.Close())

		conn, err := net.ListenPacket("udp", addr)
		if err != nil {
			continue
		}
		require.NoError(t, conn.Close())
		return addr
	}
	t.Fatal("no address with both tcp and udp ports free")
	return ""
}

// Listen registers its listeners under the same lock that starts serving, so a
// non-empty ListenerProtocols means the sockets are bound. A Listen that returns
// before that has failed to bind, and its error is reported instead of a timeout.
func waitForListeners(t *testing.T, srv *Server, errChan <-chan error) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for len(srv.ListenerProtocols()) == 0 {
		select {
		case err := <-errChan:
			t.Fatalf("Listen returned before binding: %v", err)
		case <-deadline:
			t.Fatal("listeners were not bound")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func waitForListenToReturn(t *testing.T, errChan <-chan error) error {
	t.Helper()
	select {
	case err := <-errChan:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Listen did not return")
		return nil
	}
}

// The QUIC listener releases its UDP socket from the read loop after Close returns,
// so both sockets are polled instead of checked once.
func requireAddressFree(t *testing.T, addr string) {
	t.Helper()
	require.Eventually(t, func() bool {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return false
		}
		_ = ln.Close()

		conn, err := net.ListenPacket("udp", addr)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, 5*time.Second, 10*time.Millisecond, "address %s must be released", addr)
}

// A nil TLS config only yields a QUIC listener in the devcert build, so the tests
// that need both listeners pass a real one and bind them regardless of build tags.
func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key}},
	}
}
