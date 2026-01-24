package tunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

func TestAuthMethodString(t *testing.T) {
	tests := []struct {
		method   AuthMethod
		expected string
	}{
		{AuthMethodUnknown, "Unknown"},
		{AuthMethodSetupKey, "SetupKey"},
		{AuthMethodMTLS, "mTLS"},
		{AuthMethod(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.method.String())
		})
	}
}

func TestHasMachineCert_NoPaths(t *testing.T) {
	cfg := &MachineConfig{
		Config: &profilemanager.Config{
			ClientCertPath:    "",
			ClientCertKeyPath: "",
		},
	}

	assert.False(t, hasMachineCert(cfg))
}

func TestHasMachineCert_InvalidPath(t *testing.T) {
	cfg := &MachineConfig{
		Config: &profilemanager.Config{
			ClientCertPath:    "/nonexistent/cert.pem",
			ClientCertKeyPath: "/nonexistent/key.pem",
		},
	}

	assert.False(t, hasMachineCert(cfg))
}

func TestHasMachineCert_ValidCert(t *testing.T) {
	// Create a temporary directory for test certificates
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	// Generate a test certificate with SAN DNSName
	err := generateTestCertificate(certPath, keyPath, []string{"test-machine.corp.local"}, time.Hour)
	require.NoError(t, err)

	cfg := &MachineConfig{
		Config: &profilemanager.Config{
			ClientCertPath:    certPath,
			ClientCertKeyPath: keyPath,
		},
	}

	assert.True(t, hasMachineCert(cfg))
}

func TestHasMachineCert_ExpiredCert(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	// Generate an expired certificate (valid for -1 hour, i.e., already expired)
	err := generateTestCertificateWithTimes(certPath, keyPath, []string{"test-machine.corp.local"},
		time.Now().Add(-2*time.Hour), time.Now().Add(-1*time.Hour))
	require.NoError(t, err)

	cfg := &MachineConfig{
		Config: &profilemanager.Config{
			ClientCertPath:    certPath,
			ClientCertKeyPath: keyPath,
		},
	}

	assert.False(t, hasMachineCert(cfg))
}

func TestHasMachineCert_NoDNSNames(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	// Generate a certificate without SAN DNSNames
	err := generateTestCertificate(certPath, keyPath, nil, time.Hour)
	require.NoError(t, err)

	cfg := &MachineConfig{
		Config: &profilemanager.Config{
			ClientCertPath:    certPath,
			ClientCertKeyPath: keyPath,
		},
	}

	assert.False(t, hasMachineCert(cfg))
}

func TestHasMachineCert_ThumbprintMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	err := generateTestCertificate(certPath, keyPath, []string{"test-machine.corp.local"}, time.Hour)
	require.NoError(t, err)

	cfg := &MachineConfig{
		Config: &profilemanager.Config{
			ClientCertPath:    certPath,
			ClientCertKeyPath: keyPath,
		},
		MachineCertThumbprint: "0000000000000000000000000000000000000000000000000000000000000000",
	}

	assert.False(t, hasMachineCert(cfg))
}

func TestBuildMTLSURL(t *testing.T) {
	tests := []struct {
		name      string
		mgmURL    string
		mtlsPort  int
		expected  string
		expectErr bool
	}{
		{
			name:     "standard URL",
			mgmURL:   "https://api.netbird.io:443",
			mtlsPort: 33074,
			expected: "api.netbird.io:33074",
		},
		{
			name:     "URL without port",
			mgmURL:   "https://api.netbird.io",
			mtlsPort: 33074,
			expected: "api.netbird.io:33074",
		},
		{
			name:     "localhost",
			mgmURL:   "https://localhost:33073",
			mtlsPort: 33074,
			expected: "localhost:33074",
		},
		{
			name:     "IP address",
			mgmURL:   "https://192.168.1.100:443",
			mtlsPort: 33074,
			expected: "192.168.1.100:33074",
		},
		{
			name:     "custom port",
			mgmURL:   "https://mgmt.example.com:8443",
			mtlsPort: 8444,
			expected: "mgmt.example.com:8444",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.mgmURL)
			require.NoError(t, err)

			result, err := buildMTLSURL(u, tt.mtlsPort)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestBuildMTLSURL_NilURL(t *testing.T) {
	_, err := buildMTLSURL(nil, 33074)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestBootstrap_NilConfig(t *testing.T) {
	ctx := context.Background()
	_, err := Bootstrap(ctx, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config is required")
}

func TestBootstrap_NilEmbeddedConfig(t *testing.T) {
	ctx := context.Background()
	cfg := &MachineConfig{Config: nil}
	_, err := Bootstrap(ctx, cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config is required")
}

func TestBootstrap_NoSetupKeyNoCert(t *testing.T) {
	ctx := context.Background()
	cfg := &MachineConfig{
		Config: &profilemanager.Config{
			ClientCertPath:    "",
			ClientCertKeyPath: "",
		},
		SetupKey: "",
	}
	_, err := Bootstrap(ctx, cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no machine certificate available and no setup key provided")
}

func TestBootstrapWithSetupKey_InvalidSetupKey(t *testing.T) {
	ctx := context.Background()
	cfg := &MachineConfig{
		Config: &profilemanager.Config{
			ClientCertPath:    "",
			ClientCertKeyPath: "",
		},
		SetupKey: "not-a-uuid",
	}
	_, err := bootstrapWithSetupKey(ctx, cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid setup key format")
}

func TestDefaultMTLSPort(t *testing.T) {
	assert.Equal(t, 33074, DefaultMTLSPort)
}

// Helper function to generate a test certificate
func generateTestCertificate(certPath, keyPath string, dnsNames []string, validity time.Duration) error {
	return generateTestCertificateWithTimes(certPath, keyPath, dnsNames,
		time.Now().Add(-time.Hour), time.Now().Add(validity))
}

func generateTestCertificateWithTimes(certPath, keyPath string, dnsNames []string, notBefore, notAfter time.Time) error {
	// Generate ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Test Machine",
			Organization: []string{"Test Org"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write certificate
	certFile, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %w", err)
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to encode certificate: %w", err)
	}

	// Write private key
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyFile.Close()

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	return nil
}
