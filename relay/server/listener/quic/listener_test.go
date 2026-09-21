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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	relaylistener "github.com/netbirdio/netbird/relay/server/listener"
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

	select {
	case err := <-errChan:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return on a listener that was already shut down")
	}
	requireUDPAddressFree(t, addr)
}

func TestListener_Unbound(t *testing.T) {
	l := &Listener{Address: "127.0.0.1:0", TLSConfig: testTLSConfig(t)}
	assert.Error(t, l.Serve(func(relaylistener.Conn) {}), "Serve must refuse an unbound listener")
	assert.NoError(t, l.Shutdown(context.Background()), "Shutdown of an unbound listener is a no-op")
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

// quic-go closes the UDP socket from its read loop after Close returns, so the
// address is polled rather than checked once.
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
