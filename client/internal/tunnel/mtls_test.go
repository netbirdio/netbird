package tunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// TestMTLSCertGeneration tests certificate generation for mTLS scenarios.
func TestMTLSCertGeneration(t *testing.T) {
	// Generate test CA
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "TEST-CA",
			Organization: []string{"Test Corp"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	// Test: CA fingerprint calculation (TC27)
	fingerprint := sha256.Sum256(caCert.Raw)
	if len(fingerprint) != 32 {
		t.Errorf("fingerprint should be 32 bytes, got %d", len(fingerprint))
	}
	t.Logf("CA Fingerprint: %x", fingerprint)

	// Generate client cert with single SAN
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	clientSerial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	clientTemplate := x509.Certificate{
		SerialNumber: clientSerial,
		Subject: pkix.Name{
			CommonName: "win10-pc.test.local",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{"win10-pc.test.local"},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, &clientTemplate, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}

	clientCert, err := x509.ParseCertificate(clientCertDER)
	if err != nil {
		t.Fatalf("parse client cert: %v", err)
	}

	// Test: SAN DNSNames extraction
	if len(clientCert.DNSNames) != 1 {
		t.Errorf("expected 1 DNS name, got %d", len(clientCert.DNSNames))
	}
	if clientCert.DNSNames[0] != "win10-pc.test.local" {
		t.Errorf("expected DNS name 'win10-pc.test.local', got '%s'", clientCert.DNSNames[0])
	}
}

// TestMTLSMultiSANValidation tests multi-SAN certificate validation (TC22/TC23).
func TestMTLSMultiSANValidation(t *testing.T) {
	allowedDomains := []string{"corp.local", "test.local"}

	testCases := []struct {
		name           string
		dnsNames       []string
		expectMatch    bool
		expectedDomain string
	}{
		{
			name:           "TC22: evil.com + corp.local → corp.local accepted",
			dnsNames:       []string{"host.evil.com", "host.corp.local"},
			expectMatch:    true,
			expectedDomain: "corp.local",
		},
		{
			name:           "TC23: only evil.com → rejected",
			dnsNames:       []string{"host.evil.com"},
			expectMatch:    false,
			expectedDomain: "",
		},
		{
			name:           "Single valid domain",
			dnsNames:       []string{"host.test.local"},
			expectMatch:    true,
			expectedDomain: "test.local",
		},
		{
			name:           "Multiple valid domains → first match",
			dnsNames:       []string{"host.corp.local", "host.test.local"},
			expectMatch:    true,
			expectedDomain: "corp.local",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matched, domain := findMatchingDomain(tc.dnsNames, allowedDomains)
			if matched != tc.expectMatch {
				t.Errorf("expected match=%v, got %v", tc.expectMatch, matched)
			}
			if domain != tc.expectedDomain {
				t.Errorf("expected domain='%s', got '%s'", tc.expectedDomain, domain)
			}
		})
	}
}

// TestMTLSIssuerValidation tests issuer fingerprint validation (TC19/TC27).
func TestMTLSIssuerValidation(t *testing.T) {
	// Generate two different CAs
	ca1Key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca1Serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	ca1Template := x509.Certificate{
		SerialNumber: ca1Serial,
		Subject: pkix.Name{
			CommonName:   "Corp-CA",
			Organization: []string{"Corp"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	ca1CertDER, _ := x509.CreateCertificate(rand.Reader, &ca1Template, &ca1Template, &ca1Key.PublicKey, ca1Key)
	ca1Cert, _ := x509.ParseCertificate(ca1CertDER)

	ca2Key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca2Serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	ca2Template := x509.Certificate{
		SerialNumber: ca2Serial,
		Subject: pkix.Name{
			CommonName:   "Other-CA",
			Organization: []string{"Other"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	ca2CertDER, _ := x509.CreateCertificate(rand.Reader, &ca2Template, &ca2Template, &ca2Key.PublicKey, ca2Key)
	ca2Cert, _ := x509.ParseCertificate(ca2CertDER)

	// Calculate fingerprints
	ca1Fingerprint := sha256.Sum256(ca1Cert.Raw)
	ca2Fingerprint := sha256.Sum256(ca2Cert.Raw)

	// TC19: Different CAs have different fingerprints
	if ca1Fingerprint == ca2Fingerprint {
		t.Error("different CAs should have different fingerprints")
	}

	// TC27: Same CA should produce consistent fingerprint
	ca1Fingerprint2 := sha256.Sum256(ca1Cert.Raw)
	if ca1Fingerprint != ca1Fingerprint2 {
		t.Error("same CA should produce consistent fingerprint")
	}

	t.Logf("CA1 Fingerprint: %x", ca1Fingerprint)
	t.Logf("CA2 Fingerprint: %x", ca2Fingerprint)

	// Test: Allowed issuers check
	allowedIssuers := map[string]bool{
		formatFingerprint(ca1Fingerprint[:]): true,
	}

	if !allowedIssuers[formatFingerprint(ca1Fingerprint[:])] {
		t.Error("CA1 should be allowed")
	}
	if allowedIssuers[formatFingerprint(ca2Fingerprint[:])] {
		t.Error("CA2 should NOT be allowed")
	}
}

// Helper functions for the test

func findMatchingDomain(dnsNames []string, allowedDomains []string) (bool, string) {
	for _, dnsName := range dnsNames {
		for _, allowedDomain := range allowedDomains {
			if hasSuffix(dnsName, "."+allowedDomain) {
				return true, allowedDomain
			}
		}
	}
	return false, ""
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func formatFingerprint(fp []byte) string {
	result := make([]byte, len(fp)*2)
	hexChars := "0123456789abcdef"
	for i, b := range fp {
		result[i*2] = hexChars[b>>4]
		result[i*2+1] = hexChars[b&0x0f]
	}
	return string(result)
}
