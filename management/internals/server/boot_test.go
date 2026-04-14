package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateSelfSignedCert creates a temporary self-signed TLS cert+key pair on disk
// and returns their paths. The caller is responsible for removing the files.
func generateSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate key")

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	require.NoError(t, err, "create cert")

	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err, "marshal key")

	certTmp, err := os.CreateTemp(t.TempDir(), "cert*.pem")
	require.NoError(t, err)
	require.NoError(t, pem.Encode(certTmp, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	require.NoError(t, certTmp.Close())

	keyTmp, err := os.CreateTemp(t.TempDir(), "key*.pem")
	require.NoError(t, err)
	require.NoError(t, pem.Encode(keyTmp, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	require.NoError(t, keyTmp.Close())

	return certTmp.Name(), keyTmp.Name()
}

func TestLoadTLSConfig_RequestClientCert(t *testing.T) {
	certFile, keyFile := generateSelfSignedCert(t)

	cfg, err := loadTLSConfig(certFile, keyFile)
	require.NoError(t, err)

	assert.Equal(t, tls.RequestClientCert, cfg.ClientAuth,
		"loadTLSConfig must use RequestClientCert to allow mTLS without breaking old clients")
}

func TestLoadTLSConfig_HTTP2Supported(t *testing.T) {
	certFile, keyFile := generateSelfSignedCert(t)

	cfg, err := loadTLSConfig(certFile, keyFile)
	require.NoError(t, err)

	assert.Contains(t, cfg.NextProtos, "h2", "HTTP/2 must be enabled")
}

func TestLoadTLSConfig_InvalidFiles(t *testing.T) {
	_, err := loadTLSConfig("/nonexistent/cert.pem", "/nonexistent/key.pem")
	assert.Error(t, err, "must return error for missing cert files")
}
