package quic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	relaylistener "github.com/netbirdio/netbird/relay/server/listener"
	"github.com/netbirdio/netbird/shared/relay/messages"
	quictls "github.com/netbirdio/netbird/shared/relay/tls"
)

func TestListener_ShutdownBeforeServe(t *testing.T) {
	l := &Listener{Address: "127.0.0.1:0", TLSConfig: testTLSConfig(t)}
	require.NoError(t, l.Bind())
	addr := l.listener.Addr().String()
	require.NoError(t, l.Shutdown(context.Background()))

	errChan := make(chan error, 1)
	go func() {
		errChan <- l.Serve(func(relaylistener.Conn) {})
	}()

	assert.NoError(t, waitForServeToReturn(t, errChan))
	requireUDPAddressFree(t, addr)
}

func TestListener_ShutdownStopsServe(t *testing.T) {
	l := &Listener{Address: "127.0.0.1:0", TLSConfig: testTLSConfig(t)}
	require.NoError(t, l.Bind())
	addr := l.listener.Addr().String()

	accepted := make(chan relaylistener.Conn, 1)
	errChan := make(chan error, 1)
	go func() {
		errChan <- l.Serve(func(conn relaylistener.Conn) { accepted <- conn })
	}()

	// quic-go completes handshakes on a bound socket before Accept is called, so
	// only a session handed to acceptFn proves Serve is blocked in Accept when
	// Shutdown arrives.
	dialTestSession(t, addr)
	var conn relaylistener.Conn
	select {
	case conn = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("listener did not accept the test session")
	}

	require.NoError(t, l.Shutdown(context.Background()))
	assert.NoError(t, waitForServeToReturn(t, errChan))

	// Shutdown leaves accepted sessions alive, as the relay closes its peers itself,
	// and quic-go keeps the UDP socket bound until the last session is gone.
	require.NoError(t, conn.Close())
	requireUDPAddressFree(t, addr)
}

func TestListener_Unbound(t *testing.T) {
	l := &Listener{Address: "127.0.0.1:0", TLSConfig: testTLSConfig(t)}
	assert.Error(t, l.Serve(func(relaylistener.Conn) {}), "Serve must refuse an unbound listener")
	assert.NoError(t, l.Shutdown(context.Background()), "Shutdown of an unbound listener is a no-op")
}

func TestConn_WritesChunkedPeerStateMessages(t *testing.T) {
	l := &Listener{Address: "127.0.0.1:0", TLSConfig: testTLSConfig(t)}
	require.NoError(t, l.Bind())
	t.Cleanup(func() { _ = l.Shutdown(context.Background()) })

	accepted := make(chan relaylistener.Conn, 1)
	go func() {
		_ = l.Serve(func(conn relaylistener.Conn) { accepted <- conn })
	}()

	session := dialTestSession(t, l.listener.Addr().String())
	var conn relaylistener.Conn
	select {
	case conn = <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("listener did not accept the test session")
	}
	t.Cleanup(func() { _ = conn.Close() })

	// More IDs than a message at the relay protocol limit of 8820 bytes holds, so
	// the messages written are the ones sized by the connection's own limit.
	ids := make([]messages.PeerID, 245)
	for i := range ids {
		ids[i] = messages.HashID(strconv.Itoa(i))
	}
	msgs, err := messages.MarshalPeersOnline(ids, conn.MaxMessageSize())
	require.NoError(t, err)
	require.Greater(t, len(msgs), 1, "the connection limit must force a split")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var received []messages.PeerID
	for i, msg := range msgs {
		_, err := conn.Write(ctx, msg)
		require.NoError(t, err, "message %d of %d bytes must fit a QUIC datagram", i, len(msg))

		dgram, err := session.ReceiveDatagram(ctx)
		require.NoError(t, err)
		chunk, err := messages.UnmarshalPeersOnlineMsg(dgram)
		require.NoError(t, err)
		received = append(received, chunk...)
	}
	assert.Equal(t, ids, received, "every peer ID must reach the client")
}

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
		NextProtos:   []string{quictls.NBalpn},
	}
}

func dialTestSession(t *testing.T, addr string) *quic.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tlsCfg := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{quictls.NBalpn}}
	session, err := quic.DialAddr(ctx, addr, tlsCfg, &quic.Config{EnableDatagrams: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.CloseWithError(0, "") })
	return session
}

func waitForServeToReturn(t *testing.T, errChan <-chan error) error {
	t.Helper()
	select {
	case err := <-errChan:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
		return nil
	}
}

// quic-go retires a closed session's connection IDs on a timer and closes the UDP
// socket from its read loop once the last one is gone, so the address is polled
// rather than checked once.
func requireUDPAddressFree(t *testing.T, addr string) {
	t.Helper()
	require.Eventually(t, func() bool {
		conn, err := net.ListenPacket("udp", addr)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, 5*time.Second, 10*time.Millisecond, "udp address %s must be released", addr)
}
