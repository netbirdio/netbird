package cmd

import (
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

func TestStartServerWithCertManager_CustomAddress(t *testing.T) {
	setLetsencryptListen(t, 10000, "127.0.0.1:0")

	listener, err := startServerWithCertManager(&autocert.Manager{}, http.NotFoundHandler())
	require.NoError(t, err)
	require.NotNil(t, listener, "challenge listener should be created on the configured address")
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
	require.Nil(t, listener, "no listener should be returned when the bind fails")
}

func TestCertManagerTLSConfigAnswersTLSALPN01(t *testing.T) {
	// Disabling the separate listener relies on the main listener answering
	// TLS-ALPN-01 challenges through the cert manager's TLS config.
	cfg := (&autocert.Manager{}).TLSConfig()
	require.Contains(t, cfg.NextProtos, acme.ALPNProto, "cert manager TLS config should offer the ACME TLS-ALPN protocol")
}
