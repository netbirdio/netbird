//go:build windows

// Package tunnel provides machine tunnel functionality for Windows pre-login VPN.
package tunnel

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// TrustStore represents a Windows certificate store.
type TrustStore string

const (
	// TrustStoreRoot is the Trusted Root Certification Authorities store.
	TrustStoreRoot TrustStore = "Root"
	// TrustStoreCA is the Intermediate Certification Authorities store.
	TrustStoreCA TrustStore = "CA"
)

// GetCertFingerprint returns the SHA-256 fingerprint of a certificate as a hex string.
func GetCertFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%X", hash)
}

// GetCertPin returns the SPKI pin (sha256//BASE64) for a certificate file.
func GetCertPin(certPath string) (string, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("read cert file: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	return GetCertPinFromDER(block.Bytes), nil
}

// GetCertPinFromDER returns the SPKI pin (sha256//BASE64) for a DER-encoded certificate.
func GetCertPinFromDER(certDER []byte) string {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return ""
	}

	// SPKI pin is the SHA-256 hash of the Subject Public Key Info
	hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256//" + base64.StdEncoding.EncodeToString(hash[:])
}

// VerifyServerCert verifies a server certificate against a pin.
// If pin is empty, verification passes (no pinning).
func VerifyServerCert(cert *x509.Certificate, pin string) error {
	if pin == "" {
		return nil
	}

	actualPin := GetCertPinFromDER(cert.Raw)
	if actualPin != pin {
		return fmt.Errorf("certificate pin mismatch: expected %s, got %s", pin, actualPin)
	}

	return nil
}

// VerifyServerCertChain verifies a certificate chain against a pin.
// The pin is checked against the leaf certificate.
func VerifyServerCertChain(chain []*x509.Certificate, pin string) error {
	if len(chain) == 0 {
		return fmt.Errorf("empty certificate chain")
	}

	return VerifyServerCert(chain[0], pin)
}

// InstallCACert installs a CA certificate into the Windows certificate store.
// Requires Administrator privileges.
func InstallCACert(certPath string, store TrustStore) error {
	// Use certutil to import the certificate
	cmd := exec.Command("certutil", "-addstore", string(store), certPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("certutil -addstore failed: %w\nOutput: %s", err, string(output))
	}

	return nil
}

// RemoveCACert removes a CA certificate from the Windows certificate store.
// Requires Administrator privileges.
func RemoveCACert(thumbprint string, store TrustStore) error {
	// Normalize thumbprint (remove spaces, colons, etc.)
	thumbprint = strings.ReplaceAll(thumbprint, " ", "")
	thumbprint = strings.ReplaceAll(thumbprint, ":", "")

	// Use certutil to delete the certificate
	cmd := exec.Command("certutil", "-delstore", string(store), thumbprint)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("certutil -delstore failed: %w\nOutput: %s", err, string(output))
	}

	return nil
}
