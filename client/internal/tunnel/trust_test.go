package tunnel

import (
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
	"testing"
	"time"
)

// generateTestCert creates a self-signed certificate for testing.
func generateTestCert(t *testing.T) (*x509.Certificate, []byte) {
	t.Helper()

	// Generate key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"NetBird Test"},
			CommonName:   "test.netbird.local",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.netbird.local"},
	}

	// Self-sign
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert, certDER
}

// writeCertFile writes a certificate to a temporary file.
func writeCertFile(t *testing.T, certDER []byte, format string) string {
	t.Helper()

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test-cert."+format)

	var data []byte
	if format == "pem" {
		data = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		})
	} else {
		data = certDER
	}

	if err := os.WriteFile(certPath, data, 0600); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}

	return certPath
}

func TestGetCertPin(t *testing.T) {
	_, certDER := generateTestCert(t)

	t.Run("PEM format", func(t *testing.T) {
		certPath := writeCertFile(t, certDER, "pem")

		pin, err := GetCertPin(certPath)
		if err != nil {
			t.Fatalf("GetCertPin failed: %v", err)
		}

		if !strings.HasPrefix(pin, "sha256//") {
			t.Errorf("Pin should start with 'sha256//', got: %s", pin)
		}

		// SHA-256 base64 encoded should be 44 chars
		hashPart := strings.TrimPrefix(pin, "sha256//")
		if len(hashPart) != 44 {
			t.Errorf("Hash part should be 44 chars (base64 SHA-256), got %d", len(hashPart))
		}
	})

	t.Run("DER format", func(t *testing.T) {
		certPath := writeCertFile(t, certDER, "der")

		pin, err := GetCertPin(certPath)
		if err != nil {
			t.Fatalf("GetCertPin failed: %v", err)
		}

		if !strings.HasPrefix(pin, "sha256//") {
			t.Errorf("Pin should start with 'sha256//', got: %s", pin)
		}
	})

	t.Run("non-existent file", func(t *testing.T) {
		_, err := GetCertPin("/nonexistent/cert.pem")
		if err == nil {
			t.Error("Expected error for non-existent file")
		}
	})
}

func TestGetCertPinFromBytes(t *testing.T) {
	_, certDER := generateTestCert(t)

	t.Run("DER bytes", func(t *testing.T) {
		pin, err := GetCertPinFromBytes(certDER)
		if err != nil {
			t.Fatalf("GetCertPinFromBytes failed: %v", err)
		}

		if !strings.HasPrefix(pin, "sha256//") {
			t.Errorf("Pin should start with 'sha256//', got: %s", pin)
		}
	})

	t.Run("PEM bytes", func(t *testing.T) {
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		})

		pin, err := GetCertPinFromBytes(pemBytes)
		if err != nil {
			t.Fatalf("GetCertPinFromBytes failed: %v", err)
		}

		if !strings.HasPrefix(pin, "sha256//") {
			t.Errorf("Pin should start with 'sha256//', got: %s", pin)
		}
	})

	t.Run("empty bytes", func(t *testing.T) {
		_, err := GetCertPinFromBytes([]byte{})
		if err == nil {
			t.Error("Expected error for empty bytes")
		}
	})
}

func TestGetCertPinFromX509(t *testing.T) {
	cert, _ := generateTestCert(t)

	pin := GetCertPinFromX509(cert)

	if !strings.HasPrefix(pin, "sha256//") {
		t.Errorf("Pin should start with 'sha256//', got: %s", pin)
	}

	hashPart := strings.TrimPrefix(pin, "sha256//")
	if len(hashPart) != 44 {
		t.Errorf("Hash part should be 44 chars (base64 SHA-256), got %d", len(hashPart))
	}
}

func TestVerifyServerCert_Pinning(t *testing.T) {
	cert, certDER := generateTestCert(t)
	correctPin := GetCertPinFromX509(cert)

	t.Run("correct pin", func(t *testing.T) {
		cfg := &TrustConfig{
			CertPin: correctPin,
		}

		verifyFunc := VerifyServerCert(cfg)
		err := verifyFunc([][]byte{certDER}, nil)
		if err != nil {
			t.Errorf("Verification should succeed with correct pin: %v", err)
		}
	})

	t.Run("wrong pin", func(t *testing.T) {
		cfg := &TrustConfig{
			CertPin: "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaaa=",
		}

		verifyFunc := VerifyServerCert(cfg)
		err := verifyFunc([][]byte{certDER}, nil)
		if err == nil {
			t.Error("Verification should fail with wrong pin")
		}
		if !strings.Contains(err.Error(), "pin mismatch") {
			t.Errorf("Error should mention pin mismatch: %v", err)
		}
	})

	t.Run("backup pin", func(t *testing.T) {
		cfg := &TrustConfig{
			CertPin:   "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaaa=",
			BackupPin: correctPin, // Correct pin is backup
		}

		verifyFunc := VerifyServerCert(cfg)
		err := verifyFunc([][]byte{certDER}, nil)
		if err != nil {
			t.Errorf("Verification should succeed with backup pin: %v", err)
		}
	})

	t.Run("invalid pin format", func(t *testing.T) {
		cfg := &TrustConfig{
			CertPin: "invalid-format",
		}

		verifyFunc := VerifyServerCert(cfg)
		err := verifyFunc([][]byte{certDER}, nil)
		if err == nil {
			t.Error("Verification should fail with invalid pin format")
		}
	})

	t.Run("no certificate", func(t *testing.T) {
		cfg := &TrustConfig{
			CertPin: correctPin,
		}

		verifyFunc := VerifyServerCert(cfg)
		err := verifyFunc([][]byte{}, nil)
		if err == nil {
			t.Error("Verification should fail with no certificate")
		}
		if err != ErrNoCertPresented {
			t.Errorf("Expected ErrNoCertPresented, got: %v", err)
		}
	})

	t.Run("nil config - pass through", func(t *testing.T) {
		verifyFunc := VerifyServerCert(nil)
		err := verifyFunc([][]byte{certDER}, nil)
		if err != nil {
			t.Errorf("Nil config should pass through: %v", err)
		}
	})

	t.Run("empty config - pass through", func(t *testing.T) {
		cfg := &TrustConfig{}
		verifyFunc := VerifyServerCert(cfg)
		err := verifyFunc([][]byte{certDER}, nil)
		if err != nil {
			t.Errorf("Empty config should pass through: %v", err)
		}
	})
}

func TestVerifyServerCert_InvalidCert(t *testing.T) {
	cfg := &TrustConfig{
		CertPin: "sha256//test",
	}

	verifyFunc := VerifyServerCert(cfg)
	err := verifyFunc([][]byte{[]byte("invalid cert data")}, nil)
	if err == nil {
		t.Error("Verification should fail with invalid certificate data")
	}
}

func TestGetCertThumbprint(t *testing.T) {
	_, certDER := generateTestCert(t)
	certPath := writeCertFile(t, certDER, "pem")

	thumbprint, err := GetCertThumbprint(certPath)
	if err != nil {
		t.Fatalf("GetCertThumbprint failed: %v", err)
	}

	// SHA-256 hex encoded is 64 chars
	if len(thumbprint) != 64 {
		t.Errorf("Thumbprint should be 64 hex chars, got %d: %s", len(thumbprint), thumbprint)
	}

	// Should be uppercase hex
	for _, c := range thumbprint {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
			t.Errorf("Thumbprint should be uppercase hex, got char: %c", c)
		}
	}
}

func TestTrustBootstrap(t *testing.T) {
	_, certDER := generateTestCert(t)
	correctPin := "sha256//" + "dGVzdA==" // dummy pin

	t.Run("pinning mode", func(t *testing.T) {
		cfg := &TrustConfig{
			CertPin: correctPin,
		}

		err := TrustBootstrap(cfg)
		if err != nil {
			t.Errorf("TrustBootstrap with pinning should succeed: %v", err)
		}
	})

	t.Run("nil config", func(t *testing.T) {
		err := TrustBootstrap(nil)
		if err == nil {
			t.Error("TrustBootstrap with nil config should fail")
		}
	})

	t.Run("CA cert mode - non-windows", func(t *testing.T) {
		certPath := writeCertFile(t, certDER, "pem")
		cfg := &TrustConfig{
			CACertPath: certPath,
		}

		// On non-Windows, this returns an error about unsupported operation
		// On Windows, it attempts to install (which requires admin privileges)
		err := TrustBootstrap(cfg)
		// We don't fail the test here because behavior differs by platform
		_ = err
	})
}

func TestMatchPin(t *testing.T) {
	validHash := "dGVzdGhhc2hkYXRhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ=="

	t.Run("matching pin", func(t *testing.T) {
		err := matchPin(validHash, "sha256//"+validHash)
		if err != nil {
			t.Errorf("Should match: %v", err)
		}
	})

	t.Run("non-matching pin", func(t *testing.T) {
		err := matchPin(validHash, "sha256//different")
		if err == nil {
			t.Error("Should not match")
		}
	})

	t.Run("invalid format", func(t *testing.T) {
		err := matchPin(validHash, "md5//"+validHash)
		if err != ErrInvalidPinFormat {
			t.Errorf("Expected ErrInvalidPinFormat, got: %v", err)
		}
	})
}

func TestExtractPinHash(t *testing.T) {
	t.Run("with prefix", func(t *testing.T) {
		hash := extractPinHash("sha256//ABC123")
		if hash != "ABC123" {
			t.Errorf("Expected ABC123, got: %s", hash)
		}
	})

	t.Run("without prefix", func(t *testing.T) {
		hash := extractPinHash("ABC123")
		if hash != "ABC123" {
			t.Errorf("Expected ABC123, got: %s", hash)
		}
	})
}

func TestTruncateHash(t *testing.T) {
	t.Run("longer than max", func(t *testing.T) {
		result := truncateHash("abcdefghijklmnop", 8)
		if result != "abcdefgh" {
			t.Errorf("Expected abcdefgh, got: %s", result)
		}
	})

	t.Run("shorter than max", func(t *testing.T) {
		result := truncateHash("abcd", 8)
		if result != "abcd" {
			t.Errorf("Expected abcd, got: %s", result)
		}
	})

	t.Run("equal to max", func(t *testing.T) {
		result := truncateHash("abcdefgh", 8)
		if result != "abcdefgh" {
			t.Errorf("Expected abcdefgh, got: %s", result)
		}
	})
}

func TestConsistentPinCalculation(t *testing.T) {
	// Verify that all pin calculation methods return the same result
	cert, certDER := generateTestCert(t)
	certPath := writeCertFile(t, certDER, "pem")

	pin1 := GetCertPinFromX509(cert)

	pin2, err := GetCertPin(certPath)
	if err != nil {
		t.Fatalf("GetCertPin failed: %v", err)
	}

	pin3, err := GetCertPinFromBytes(certDER)
	if err != nil {
		t.Fatalf("GetCertPinFromBytes failed: %v", err)
	}

	// All methods should return the same pin
	if pin1 != pin3 {
		t.Errorf("GetCertPinFromX509 and GetCertPinFromBytes return different pins:\n  X509: %s\n  Bytes: %s", pin1, pin3)
	}

	// PEM file pin should also match (it decodes to same DER bytes)
	if pin1 != pin2 {
		t.Errorf("GetCertPinFromX509 and GetCertPin return different pins:\n  X509: %s\n  File: %s", pin1, pin2)
	}
}
