package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCA(t *testing.T) {
	certPEM, keyPEM, fingerprint, err := GenerateCA("netbird.example", CAOptions{})
	require.NoError(t, err)
	require.NotEmpty(t, certPEM)
	require.NotEmpty(t, keyPEM)
	require.NotEmpty(t, fingerprint)

	cert, err := parseCertificatePEM(certPEM)
	require.NoError(t, err)

	assert.True(t, cert.IsCA)
	assert.Contains(t, cert.Subject.CommonName, "netbird.example Internal CA (")
	assert.Equal(t, []string{"NetBird Self-Hosted"}, cert.Subject.Organization)
	assert.True(t, cert.BasicConstraintsValid)
	assert.Equal(t, 0, cert.MaxPathLen)
	assert.True(t, cert.MaxPathLenZero)
	assert.Contains(t, cert.PermittedDNSDomains, ".netbird.example")
	assert.Contains(t, cert.PermittedDNSDomains, "netbird.example")

	key, err := parseECPrivateKeyPEM(keyPEM)
	require.NoError(t, err)
	assert.Equal(t, elliptic.P256(), key.Curve)
}

func TestGenerateCA_Fingerprint(t *testing.T) {
	certPEM, _, fingerprint1, err := GenerateCA("test.example", CAOptions{})
	require.NoError(t, err)

	fingerprint2, err := Fingerprint(certPEM)
	require.NoError(t, err)

	assert.Equal(t, fingerprint1, fingerprint2)
	assert.Len(t, fingerprint1, 64) // SHA-256 hex = 64 chars
}

func TestGenerateCA_CustomOptions(t *testing.T) {
	certPEM, _, _, err := GenerateCA("zakhar.internal", CAOptions{
		DisplayName:  "Zakhar",
		Organization: "Zakhar Corp",
		Validity:     5 * 365 * 24 * time.Hour,
	})
	require.NoError(t, err)

	cert, err := parseCertificatePEM(certPEM)
	require.NoError(t, err)

	assert.Equal(t, "Zakhar Internal CA", cert.Subject.CommonName)
	assert.Equal(t, []string{"Zakhar Corp"}, cert.Subject.Organization)

	// 5 years validity ≈ 1825 days, allow a small delta
	validity := cert.NotAfter.Sub(cert.NotBefore)
	assert.InDelta(t, (5 * 365 * 24 * time.Hour).Hours(), validity.Hours(), 24)
}

func TestGenerateCA_EmptyDomainReturnsError(t *testing.T) {
	_, _, _, err := GenerateCA("", CAOptions{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "dnsDomain is required")
}

func TestGenerateCA_DomainOnlyFallback(t *testing.T) {
	// No display name or org → CN falls back to domain + unique suffix, org to default
	certPEM, _, _, err := GenerateCA("mynetwork.selfhosted", CAOptions{})
	require.NoError(t, err)

	cert, err := parseCertificatePEM(certPEM)
	require.NoError(t, err)

	assert.Contains(t, cert.Subject.CommonName, "mynetwork.selfhosted Internal CA (")
	assert.Len(t, cert.Subject.CommonName, len("mynetwork.selfhosted Internal CA (")+len("abcdef)"))
	assert.Equal(t, []string{"NetBird Self-Hosted"}, cert.Subject.Organization)
}

func TestGenerateCA_CustomNameNoSuffix(t *testing.T) {
	// When DisplayName is provided, no suffix is added
	certPEM, _, _, err := GenerateCA("zakhar.internal", CAOptions{DisplayName: "Zakhar"})
	require.NoError(t, err)

	cert, err := parseCertificatePEM(certPEM)
	require.NoError(t, err)

	assert.Equal(t, "Zakhar Internal CA", cert.Subject.CommonName)
	assert.NotContains(t, cert.Subject.CommonName, "(")
}

func TestInternalCASigner_Sign(t *testing.T) {
	certPEM, keyPEM, _, err := GenerateCA("netbird.example", CAOptions{})
	require.NoError(t, err)

	signer, err := NewInternalCASigner(certPEM, keyPEM, "test-ca-id", 0)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "peer1.netbird.example"},
		DNSNames: []string{"peer1.netbird.example"},
	}, csrKey)
	require.NoError(t, err)

	parsedCSR, err := x509.ParseCertificateRequest(csr)
	require.NoError(t, err)

	result, err := signer.Sign(context.Background(), parsedCSR, "peer1.netbird.example", false)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotEmpty(t, result.CertPEM)
	require.NotEmpty(t, result.ChainPEM)

	issuedCert, err := parseCertificatePEM(result.CertPEM)
	require.NoError(t, err)

	assert.Equal(t, "peer1.netbird.example", issuedCert.Subject.CommonName)
	assert.Equal(t, []string{"peer1.netbird.example"}, issuedCert.DNSNames)
	assert.Contains(t, issuedCert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	assert.Contains(t, issuedCert.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
}

func TestInternalCASigner_SignWildcard(t *testing.T) {
	certPEM, keyPEM, _, err := GenerateCA("netbird.example", CAOptions{})
	require.NoError(t, err)

	signer, err := NewInternalCASigner(certPEM, keyPEM, "test-ca-id", 0)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "peer1.netbird.example"},
		DNSNames: []string{"peer1.netbird.example", "*.peer1.netbird.example"},
	}, csrKey)
	require.NoError(t, err)

	parsedCSR, err := x509.ParseCertificateRequest(csr)
	require.NoError(t, err)

	result, err := signer.Sign(context.Background(), parsedCSR, "peer1.netbird.example", true)
	require.NoError(t, err)

	issuedCert, err := parseCertificatePEM(result.CertPEM)
	require.NoError(t, err)

	assert.Contains(t, issuedCert.DNSNames, "peer1.netbird.example")
	assert.Contains(t, issuedCert.DNSNames, "*.peer1.netbird.example")
}

func TestInternalCASigner_SignRejectsMismatchedFQDN(t *testing.T) {
	certPEM, keyPEM, _, err := GenerateCA("netbird.example", CAOptions{})
	require.NoError(t, err)

	signer, err := NewInternalCASigner(certPEM, keyPEM, "test-ca-id", 0)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "attacker.evil.com"},
		DNSNames: []string{"attacker.evil.com"},
	}, csrKey)
	require.NoError(t, err)

	parsedCSR, err := x509.ParseCertificateRequest(csr)
	require.NoError(t, err)

	_, err = signer.Sign(context.Background(), parsedCSR, "peer1.netbird.example", false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected DNS name")
}

func TestInternalCASigner_SignRejectsWildcardWhenNotRequested(t *testing.T) {
	certPEM, keyPEM, _, err := GenerateCA("netbird.example", CAOptions{})
	require.NoError(t, err)

	signer, err := NewInternalCASigner(certPEM, keyPEM, "test-ca-id", 0)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "peer1.netbird.example"},
		DNSNames: []string{"peer1.netbird.example", "*.peer1.netbird.example"},
	}, csrKey)
	require.NoError(t, err)

	parsedCSR, err := x509.ParseCertificateRequest(csr)
	require.NoError(t, err)

	// wildcard=false but CSR contains wildcard
	_, err = signer.Sign(context.Background(), parsedCSR, "peer1.netbird.example", false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected DNS name")
}

func TestInternalCASigner_SignRejectsEmptyDNSNames(t *testing.T) {
	certPEM, keyPEM, _, err := GenerateCA("netbird.example", CAOptions{})
	require.NoError(t, err)

	signer, err := NewInternalCASigner(certPEM, keyPEM, "test-ca-id", 0)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "peer1.netbird.example"},
	}, csrKey)
	require.NoError(t, err)

	parsedCSR, err := x509.ParseCertificateRequest(csr)
	require.NoError(t, err)

	_, err = signer.Sign(context.Background(), parsedCSR, "peer1.netbird.example", false)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one DNS name")
}

func TestInternalCASigner_Type(t *testing.T) {
	certPEM, keyPEM, _, err := GenerateCA("netbird.example", CAOptions{})
	require.NoError(t, err)

	signer, err := NewInternalCASigner(certPEM, keyPEM, "test-ca-id", 0)
	require.NoError(t, err)

	assert.Equal(t, SigningTypeInternal, signer.Type())
}

func TestInternalCASigner_CertificateChainVerifies(t *testing.T) {
	certPEM, keyPEM, _, err := GenerateCA("netbird.example", CAOptions{})
	require.NoError(t, err)

	signer, err := NewInternalCASigner(certPEM, keyPEM, "test-ca-id", 0)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "peer1.netbird.example"},
		DNSNames: []string{"peer1.netbird.example"},
	}, csrKey)
	require.NoError(t, err)

	parsedCSR, err := x509.ParseCertificateRequest(csr)
	require.NoError(t, err)

	result, err := signer.Sign(context.Background(), parsedCSR, "peer1.netbird.example", false)
	require.NoError(t, err)

	// Parse the CA cert and issued cert
	caCert, err := parseCertificatePEM(result.ChainPEM)
	require.NoError(t, err)

	issuedCert, err := parseCertificatePEM(result.CertPEM)
	require.NoError(t, err)

	// Build verification pool
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	opts := x509.VerifyOptions{
		Roots:   roots,
		DNSName: "peer1.netbird.example",
	}

	chains, err := issuedCert.Verify(opts)
	require.NoError(t, err)
	assert.NotEmpty(t, chains)
}

func TestSerialNumberFromResult(t *testing.T) {
	certPEM, keyPEM, _, err := GenerateCA("netbird.example", CAOptions{})
	require.NoError(t, err)

	signer, err := NewInternalCASigner(certPEM, keyPEM, "test-ca-id", 0)
	require.NoError(t, err)

	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "peer1.netbird.example"},
		DNSNames: []string{"peer1.netbird.example"},
	}, csrKey)
	require.NoError(t, err)

	parsedCSR, err := x509.ParseCertificateRequest(csr)
	require.NoError(t, err)

	result, err := signer.Sign(context.Background(), parsedCSR, "peer1.netbird.example", false)
	require.NoError(t, err)

	serial, err := SerialNumberFromResult(result.CertPEM)
	require.NoError(t, err)
	assert.NotEmpty(t, serial)
}
