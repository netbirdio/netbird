package appleroots_test

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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/devicepki/appleroots"
)

// selfSignedPEM generates a minimal self-signed CA certificate PEM for testing.
func selfSignedPEM(t *testing.T) (certPEM string, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return
}

// signedCertPEM creates a certificate signed by the given CA and returns its PEM and key.
func signedCertPEM(t *testing.T, cn string, isCA bool, parentCert *x509.Certificate, parentKey *ecdsa.PrivateKey) (certPEM string, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, &key.PublicKey, parentKey)
	require.NoError(t, err)
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return
}

func TestBuildAppleSERootPool_FileOverride(t *testing.T) {
	certPEM, _ := selfSignedPEM(t)

	f, err := os.CreateTemp(t.TempDir(), "root*.pem")
	require.NoError(t, err)
	_, err = f.WriteString(certPEM)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	pool, err := appleroots.BuildAppleSERootPool(context.Background(), appleroots.Config{CACertFile: f.Name()})
	require.NoError(t, err)
	assert.NotNil(t, pool)
}

func TestBuildAppleSERootPool_MissingFile_ReturnsError(t *testing.T) {
	_, err := appleroots.BuildAppleSERootPool(context.Background(), appleroots.Config{
		CACertFile: "/nonexistent/path.pem",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read CA file")
}

func TestBuildAppleSERootPool_InvalidPEM_ReturnsError(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "bad*.pem")
	require.NoError(t, err)
	_, err = f.WriteString("this is not a PEM certificate")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	_, err = appleroots.BuildAppleSERootPool(context.Background(), appleroots.Config{CACertFile: f.Name()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no valid certificates")
}

// ─── LoadIntermediateCerts tests ──────────────────────────────────────────────

func TestLoadIntermediateCerts_EmptyPath_ReturnsNil(t *testing.T) {
	// No intermediate file configured → nil slice, no error.
	certs, err := appleroots.LoadIntermediateCerts(appleroots.Config{})
	require.NoError(t, err)
	assert.Nil(t, certs)
}

func TestLoadIntermediateCerts_ValidFile_ReturnsCerts(t *testing.T) {
	certPEM, _ := selfSignedPEM(t)

	f, err := os.CreateTemp(t.TempDir(), "intermediate*.pem")
	require.NoError(t, err)
	_, err = f.WriteString(certPEM)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	certs, err := appleroots.LoadIntermediateCerts(appleroots.Config{IntermediateCACertFile: f.Name()})
	require.NoError(t, err)
	require.Len(t, certs, 1)
}

func TestLoadIntermediateCerts_MissingFile_ReturnsError(t *testing.T) {
	_, err := appleroots.LoadIntermediateCerts(appleroots.Config{
		IntermediateCACertFile: "/nonexistent/intermediate.pem",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read intermediate CA file")
}

func TestLoadIntermediateCerts_InvalidPEM_ReturnsError(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "bad*.pem")
	require.NoError(t, err)
	_, err = f.WriteString("not a certificate")
	require.NoError(t, err)
	require.NoError(t, f.Close())

	_, err = appleroots.LoadIntermediateCerts(appleroots.Config{IntermediateCACertFile: f.Name()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no valid certificates")
}

// ─── verifyAppleAttestationChain integration via AttestAppleSE ───────────────
// These tests build a 3-tier chain (root → intermediate → leaf) to exercise the
// IntermediateCACertFile path without hitting Apple's servers.

// buildTestChain returns (rootPEM, intermediatePEM, leafPEM, leafKey) for testing.
func buildTestChain(t *testing.T) (rootPEM, intermediatePEM, leafPEM string, leafKey *ecdsa.PrivateKey) {
	t.Helper()

	// Root CA
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	rootPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))

	// Intermediate CA (signed by root)
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, rootCert, &interKey.PublicKey, rootKey)
	require.NoError(t, err)
	interCert, err := x509.ParseCertificate(interDER)
	require.NoError(t, err)
	intermediatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER}))

	// Leaf cert (signed by intermediate)
	leafKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, interCert, &leafKey.PublicKey, interKey)
	require.NoError(t, err)
	leafPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
	return
}

func TestLoadIntermediateCerts_MultipleInFile_ReturnsAll(t *testing.T) {
	certPEM1, _ := selfSignedPEM(t)
	certPEM2, _ := selfSignedPEM(t)

	f, err := os.CreateTemp(t.TempDir(), "intermediates*.pem")
	require.NoError(t, err)
	_, err = f.WriteString(certPEM1 + certPEM2)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	certs, err := appleroots.LoadIntermediateCerts(appleroots.Config{IntermediateCACertFile: f.Name()})
	require.NoError(t, err)
	assert.Len(t, certs, 2, "both PEM blocks should be parsed")
}
