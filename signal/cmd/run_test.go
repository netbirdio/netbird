package cmd

import (
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

func setLetsencryptListen(t *testing.T, port int, address string) {
	t.Helper()
	oldPort, oldAddress := signalPort, signalLetsencryptListen
	signalPort, signalLetsencryptListen = port, address
	t.Cleanup(func() {
		signalPort, signalLetsencryptListen = oldPort, oldAddress
	})
}

func drainStopCh(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		select {
		case <-stopCh:
		default:
		}
	})
}

func TestStartServerWithCertManager_ListenerDisabled(t *testing.T) {
	setLetsencryptListen(t, 10000, "")

	listener, err := startServerWithCertManager(&autocert.Manager{}, http.NotFoundHandler())
	require.NoError(t, err)
	require.Nil(t, listener)
}

func TestStartServerWithCertManager_CustomAddress(t *testing.T) {
	drainStopCh(t)
	setLetsencryptListen(t, 10000, "127.0.0.1:0")

	listener, err := startServerWithCertManager(&autocert.Manager{}, http.NotFoundHandler())
	require.NoError(t, err)
	require.NotNil(t, listener)
	t.Cleanup(func() { _ = listener.Close() })

	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	require.NoError(t, err)
	require.NoError(t, conn.Close())
}

func TestStartServerWithCertManager_BindFailure(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = occupied.Close() })
	setLetsencryptListen(t, 10000, occupied.Addr().String())

	listener, err := startServerWithCertManager(&autocert.Manager{}, http.NotFoundHandler())
	require.Error(t, err)
	require.Nil(t, listener)
}

func TestCertManagerTLSConfigAnswersTLSALPN01(t *testing.T) {
	// Disabling the separate listener relies on the main listener answering
	// TLS-ALPN-01 challenges through the cert manager's TLS config.
	cfg := (&autocert.Manager{}).TLSConfig()
	require.Contains(t, cfg.NextProtos, acme.ALPNProto)
}

func TestServeHTTP_ClosedListenerIsNotAFailure(t *testing.T) {
	drainStopCh(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", (&autocert.Manager{}).TLSConfig())
	require.NoError(t, err)

	serveHTTP(listener, http.NotFoundHandler())
	require.NoError(t, listener.Close())

	select {
	case code := <-stopCh:
		t.Fatalf("closing the listener reported a failure with code %d", code)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestNotifyStop_KeepsEarlyFailure(t *testing.T) {
	drainStopCh(t)

	notifyStop("failed before the run loop waits")

	select {
	case code := <-stopCh:
		require.Equal(t, 1, code)
	default:
		t.Fatal("a failure reported before the run loop waits was dropped")
	}
}
