package proxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	internalauth "github.com/netbirdio/netbird/proxy/internal/auth"
)

func TestDebugEndpointDisabledByDefault(t *testing.T) {
	s := &Server{}
	assert.False(t, s.DebugEndpointEnabled, "debug endpoint should be disabled by default")
}

func TestDebugEndpointAddr(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty defaults to localhost",
			input:    "",
			expected: "localhost:8444",
		},
		{
			name:     "explicit localhost preserved",
			input:    "localhost:9999",
			expected: "localhost:9999",
		},
		{
			name:     "explicit address preserved",
			input:    "0.0.0.0:8444",
			expected: "0.0.0.0:8444",
		},
		{
			name:     "127.0.0.1 preserved",
			input:    "127.0.0.1:8444",
			expected: "127.0.0.1:8444",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := debugEndpointAddr(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestConfigureTLS_ConfiguresClientCAsPerDomain(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeTestTLSCertificate(t, dir)

	mw := internalauth.NewMiddleware(log.StandardLogger(), nil, nil)
	caPEM := writeTestCA(t)
	mtlsConfig, err := internalauth.NewMTLSConfig(true, caPEM)
	require.NoError(t, err)
	require.NoError(t, mw.AddDomain("example.com", internalauth.AddDomainOptions{
		Schemes:             nil,
		SessionPublicKeyB64: "",
		SessionExpiration:   0,
		AccountID:           "acc1",
		ServiceID:           "svc1",
		IPRestrictions:      nil,
		MTLS:                mtlsConfig,
	}))

	s := &Server{
		CertificateDirectory: dir,
		CertificateFile:      filepath.Base(certFile),
		CertificateKeyFile:   filepath.Base(keyFile),
		Logger:               log.StandardLogger(),
		auth:                 mw,
	}

	tlsConfig, err := s.configureTLS(context.Background())
	require.NoError(t, err)
	require.NotNil(t, tlsConfig.GetConfigForClient)

	cfg, err := tlsConfig.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "example.com"})
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, tls.RequestClientCert, cfg.ClientAuth)
	assert.Equal(t, mtlsConfig.CAPool.Subjects(), cfg.ClientCAs.Subjects())

	cfg, err = tlsConfig.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "other.example.com"})
	require.NoError(t, err)
	assert.Nil(t, cfg)
}

func writeTestTLSCertificate(t *testing.T, dir string) (string, string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))
	return certPath, keyPath
}

func writeTestCA(t *testing.T) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
