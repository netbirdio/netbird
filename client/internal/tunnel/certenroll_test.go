package tunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultCertTemplateName(t *testing.T) {
	assert.Equal(t, "NetBirdMachineTunnel", DefaultCertTemplateName)
}

func TestCertRenewalThreshold(t *testing.T) {
	assert.Equal(t, 30*24*time.Hour, CertRenewalThreshold)
}

func TestMinCertValidity(t *testing.T) {
	assert.Equal(t, 7*24*time.Hour, MinCertValidity)
}

func TestComputeCertThumbprint(t *testing.T) {
	// Create a test certificate
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test.pem")
	keyPath := filepath.Join(tmpDir, "test.key")

	err := generateTestCertWithDNSNames(certPath, keyPath, []string{"test.example.com"}, time.Hour*24)
	require.NoError(t, err)

	// Read and parse certificate
	certPEM, err := os.ReadFile(certPath)
	require.NoError(t, err)

	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)

	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	// Compute thumbprint
	thumbprint := ComputeCertThumbprint(cert)

	// Verify thumbprint is 64 hex characters (SHA-256)
	assert.Len(t, thumbprint, 64)
	assert.Regexp(t, "^[0-9a-f]+$", thumbprint)
}

func TestValidateMachineCertificate_ValidCert(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test.pem")
	keyPath := filepath.Join(tmpDir, "test.key")

	err := generateTestCertWithDNSNames(certPath, keyPath, []string{"testhost.example.com"}, time.Hour*24*365)
	require.NoError(t, err)

	result, err := ValidateMachineCertificate(certPath, "testhost", "example.com")

	assert.NoError(t, err)
	assert.True(t, result.Success)
	assert.Contains(t, result.DNSNames, "testhost.example.com")
	assert.NotEmpty(t, result.Thumbprint)
}

func TestValidateMachineCertificate_ExpiredCert(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test.pem")
	keyPath := filepath.Join(tmpDir, "test.key")

	// Generate an expired certificate
	err := generateTestCertWithTimes(certPath, keyPath, []string{"testhost.example.com"},
		time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	require.NoError(t, err)

	result, err := ValidateMachineCertificate(certPath, "testhost", "example.com")

	assert.Error(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, err.Error(), "expired")
}

func TestValidateMachineCertificate_NotYetValid(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test.pem")
	keyPath := filepath.Join(tmpDir, "test.key")

	// Generate a certificate that's not yet valid
	err := generateTestCertWithTimes(certPath, keyPath, []string{"testhost.example.com"},
		time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour))
	require.NoError(t, err)

	result, err := ValidateMachineCertificate(certPath, "testhost", "example.com")

	assert.Error(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, err.Error(), "not yet valid")
}

func TestValidateMachineCertificate_NoDNSNames(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test.pem")
	keyPath := filepath.Join(tmpDir, "test.key")

	// Generate a certificate without DNS names
	err := generateTestCertWithDNSNames(certPath, keyPath, nil, time.Hour*24)
	require.NoError(t, err)

	result, err := ValidateMachineCertificate(certPath, "testhost", "example.com")

	assert.Error(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, err.Error(), "no SAN DNSNames")
}

func TestValidateMachineCertificate_WrongHostname(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test.pem")
	keyPath := filepath.Join(tmpDir, "test.key")

	err := generateTestCertWithDNSNames(certPath, keyPath, []string{"otherhost.example.com"}, time.Hour*24)
	require.NoError(t, err)

	result, err := ValidateMachineCertificate(certPath, "testhost", "example.com")

	assert.Error(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, err.Error(), "do not match expected")
}

func TestValidateMachineCertificate_FileNotFound(t *testing.T) {
	result, err := ValidateMachineCertificate("/nonexistent/cert.pem", "test", "example.com")

	assert.Error(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, err.Error(), "read certificate")
}

func TestValidateMachineCertificate_InvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "invalid.pem")

	err := os.WriteFile(certPath, []byte("not a valid PEM"), 0600)
	require.NoError(t, err)

	result, err := ValidateMachineCertificate(certPath, "test", "example.com")

	assert.Error(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, err.Error(), "decode PEM")
}

func TestNeedsRenewal_ValidCert(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test.pem")
	keyPath := filepath.Join(tmpDir, "test.key")

	// Certificate valid for 1 year - doesn't need renewal
	err := generateTestCertWithDNSNames(certPath, keyPath, []string{"test.example.com"}, time.Hour*24*365)
	require.NoError(t, err)

	needsRenewal, err := NeedsRenewal(certPath)

	assert.NoError(t, err)
	assert.False(t, needsRenewal)
}

func TestNeedsRenewal_ExpiringSoon(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test.pem")
	keyPath := filepath.Join(tmpDir, "test.key")

	// Certificate expires in 15 days - needs renewal (threshold is 30 days)
	err := generateTestCertWithTimes(certPath, keyPath, []string{"test.example.com"},
		time.Now().Add(-time.Hour), time.Now().Add(15*24*time.Hour))
	require.NoError(t, err)

	needsRenewal, err := NeedsRenewal(certPath)

	assert.NoError(t, err)
	assert.True(t, needsRenewal)
}

func TestNeedsRenewal_FileNotFound(t *testing.T) {
	needsRenewal, err := NeedsRenewal("/nonexistent/cert.pem")

	assert.Error(t, err)
	assert.True(t, needsRenewal) // Should return true if we can't read the cert
}

func TestParseCertificateFile(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test.pem")
	keyPath := filepath.Join(tmpDir, "test.key")

	dnsNames := []string{"host.domain.local", "alias.domain.local"}
	err := generateTestCertWithDNSNames(certPath, keyPath, dnsNames, time.Hour*24*365)
	require.NoError(t, err)

	info, err := ParseCertificateFile(certPath)

	assert.NoError(t, err)
	assert.NotEmpty(t, info.Thumbprint)
	assert.NotEmpty(t, info.Subject)
	assert.NotEmpty(t, info.Issuer)
	assert.Equal(t, dnsNames, info.DNSNames)
	assert.False(t, info.IsExpired)
	assert.False(t, info.NeedsRenewal)
	assert.True(t, info.RemainingValidity > 364*24*time.Hour)
}

func TestParseCertificateFile_Expired(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test.pem")
	keyPath := filepath.Join(tmpDir, "test.key")

	err := generateTestCertWithTimes(certPath, keyPath, []string{"test.example.com"},
		time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
	require.NoError(t, err)

	info, err := ParseCertificateFile(certPath)

	assert.NoError(t, err)
	assert.True(t, info.IsExpired)
	assert.True(t, info.NeedsRenewal)
	assert.True(t, info.RemainingValidity < 0)
}

func TestGenerateCertEnrollmentScript_Basic(t *testing.T) {
	config := &CertEnrollmentConfig{
		Hostname:   "win10-pc",
		DomainName: "corp.local",
	}

	script := GenerateCertEnrollmentScript(config)

	assert.Contains(t, script, "win10-pc.corp.local")
	assert.Contains(t, script, DefaultCertTemplateName)
	assert.Contains(t, script, "certreq -new")
	assert.Contains(t, script, "certreq -submit")
	assert.Contains(t, script, "certreq -accept")
	assert.Contains(t, script, "Cert:\\LocalMachine\\My")
}

func TestGenerateCertEnrollmentScript_CustomTemplate(t *testing.T) {
	config := &CertEnrollmentConfig{
		Hostname:     "server01",
		DomainName:   "example.com",
		TemplateName: "CustomMachineTemplate",
	}

	script := GenerateCertEnrollmentScript(config)

	assert.Contains(t, script, "CustomMachineTemplate")
	assert.Contains(t, script, "server01.example.com")
}

func TestGenerateCertEnrollmentScript_ContainsRequiredSteps(t *testing.T) {
	config := &CertEnrollmentConfig{
		Hostname:   "test",
		DomainName: "test.local",
	}

	script := GenerateCertEnrollmentScript(config)

	// Check that all required steps are present
	assert.Contains(t, script, "Step 1: Create INF")
	assert.Contains(t, script, "Step 2: Generate certificate request")
	assert.Contains(t, script, "Step 3: Submit request")
	assert.Contains(t, script, "Step 4: Accept certificate")
	assert.Contains(t, script, "Step 5: Find and export")
	assert.Contains(t, script, "Step 6: Export to PEM")

	// Check crypto requirements
	assert.Contains(t, script, "KeyLength = 2048")
	assert.Contains(t, script, "SHA256")
	assert.Contains(t, script, "MachineKeySet = TRUE")
}

func TestWatchCertificateExpiry(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test.pem")
	keyPath := filepath.Join(tmpDir, "test.key")

	// Create a certificate that expires in 20 days (within renewal threshold)
	err := generateTestCertWithTimes(certPath, keyPath, []string{"test.example.com"},
		time.Now().Add(-time.Hour), time.Now().Add(20*24*time.Hour))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var callbackCalled atomic.Bool

	go WatchCertificateExpiry(ctx, certPath, 500*time.Millisecond, func() {
		callbackCalled.Store(true)
	})

	// Wait for at least one check
	time.Sleep(1 * time.Second)

	assert.True(t, callbackCalled.Load(), "Callback should have been called for expiring cert")
}

func TestWatchCertificateExpiry_NoRenewalNeeded(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test.pem")
	keyPath := filepath.Join(tmpDir, "test.key")

	// Create a certificate valid for 1 year
	err := generateTestCertWithDNSNames(certPath, keyPath, []string{"test.example.com"}, time.Hour*24*365)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var callbackCalled atomic.Bool

	go WatchCertificateExpiry(ctx, certPath, 500*time.Millisecond, func() {
		callbackCalled.Store(true)
	})

	// Wait for at least one check
	time.Sleep(1 * time.Second)

	assert.False(t, callbackCalled.Load(), "Callback should NOT have been called for valid cert")
}

func TestExtractIssuerFingerprint_SingleCert(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test.pem")
	keyPath := filepath.Join(tmpDir, "test.key")

	err := generateTestCertWithDNSNames(certPath, keyPath, []string{"test.example.com"}, time.Hour*24)
	require.NoError(t, err)

	// Single cert should return error (no issuer in chain)
	_, err = ExtractIssuerFingerprint(certPath, true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certificate chain required")
}

func TestExtractIssuerFingerprint_CertChain(t *testing.T) {
	tmpDir := t.TempDir()
	chainPath := filepath.Join(tmpDir, "chain.pem")

	// Generate CA and end-entity cert
	caCert, caKey, err := generateCACertificate()
	require.NoError(t, err)

	eeCert, _, err := generateSignedCertificate(caCert, caKey, []string{"test.example.com"})
	require.NoError(t, err)

	// Write chain (EE cert first, then CA)
	chainPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: eeCert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})...)
	err = os.WriteFile(chainPath, chainPEM, 0600)
	require.NoError(t, err)

	fingerprint, err := ExtractIssuerFingerprint(chainPath, true)

	assert.NoError(t, err)
	assert.Len(t, fingerprint, 64) // SHA-256 hex
	assert.Equal(t, ComputeCertThumbprint(caCert), fingerprint)
}

func TestCertificateInfo_Fields(t *testing.T) {
	info := &CertificateInfo{
		Thumbprint:        "abc123",
		Subject:           "CN=test",
		Issuer:            "CN=CA",
		DNSNames:          []string{"test.local"},
		NotBefore:         time.Now(),
		NotAfter:          time.Now().Add(24 * time.Hour),
		SerialNumber:      "1234",
		IsExpired:         false,
		NeedsRenewal:      false,
		RemainingValidity: 24 * time.Hour,
	}

	assert.Equal(t, "abc123", info.Thumbprint)
	assert.Equal(t, "CN=test", info.Subject)
	assert.Equal(t, "CN=CA", info.Issuer)
	assert.Len(t, info.DNSNames, 1)
	assert.False(t, info.IsExpired)
}

func TestValidateMachineCertificate_CaseInsensitiveHostname(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test.pem")
	keyPath := filepath.Join(tmpDir, "test.key")

	// Certificate has lowercase DNS name
	err := generateTestCertWithDNSNames(certPath, keyPath, []string{"testhost.example.com"}, time.Hour*24*365)
	require.NoError(t, err)

	// Validate with uppercase hostname - should still match
	result, err := ValidateMachineCertificate(certPath, "TESTHOST", "EXAMPLE.COM")

	assert.NoError(t, err)
	assert.True(t, result.Success)
}

// Helper functions

func generateTestCertWithDNSNames(certPath, keyPath string, dnsNames []string, validity time.Duration) error {
	return generateTestCertWithTimes(certPath, keyPath, dnsNames,
		time.Now().Add(-time.Hour), time.Now().Add(validity))
}

func generateTestCertWithTimes(certPath, keyPath string, dnsNames []string, notBefore, notAfter time.Time) error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	keyFile, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyFile.Close()
	keyDER, _ := x509.MarshalECPrivateKey(privateKey)
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return err
	}

	return nil
}

func generateCACertificate() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	caTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"Test CA Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour * 365),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, nil, err
	}

	return caCert, caKey, nil
}

func generateSignedCertificate(caCert *x509.Certificate, caKey *ecdsa.PrivateKey, dnsNames []string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	eeKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	eeTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   strings.Join(dnsNames, ", "),
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour * 30),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}

	eeDER, err := x509.CreateCertificate(rand.Reader, &eeTemplate, caCert, &eeKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	eeCert, err := x509.ParseCertificate(eeDER)
	if err != nil {
		return nil, nil, err
	}

	return eeCert, eeKey, nil
}
