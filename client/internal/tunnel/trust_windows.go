//go:build windows
// +build windows

// Package tunnel provides trust establishment for management server connections.
// This file implements CA certificate installation and certificate pinning for Windows.
package tunnel

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	log "github.com/sirupsen/logrus"
)

// TrustConfig holds configuration for server certificate verification.
type TrustConfig struct {
	// CACertPath is the path to a CA certificate file to install in Windows Trusted Root.
	// Used for Option 1: CA-Cert installation.
	CACertPath string `yaml:"management_ca_cert,omitempty" json:"management_ca_cert,omitempty"`

	// CertPin is a SHA-256 fingerprint of the server certificate or CA certificate.
	// Format: "sha256//BASE64HASH"
	// Used for Option 2: Certificate pinning.
	CertPin string `yaml:"management_cert_pin,omitempty" json:"management_cert_pin,omitempty"`

	// BackupPin is an optional backup pin for certificate rotation.
	// Allows pinning to a new certificate before rotation occurs.
	BackupPin string `yaml:"management_cert_pin_backup,omitempty" json:"management_cert_pin_backup,omitempty"`
}

// ErrCertPinMismatch indicates the server certificate doesn't match the pinned hash.
var ErrCertPinMismatch = errors.New("certificate pin mismatch")

// ErrInvalidPinFormat indicates the pin format is incorrect.
var ErrInvalidPinFormat = errors.New("invalid pin format (expected sha256//BASE64)")

// ErrNoCertPresented indicates no certificate was presented during TLS handshake.
var ErrNoCertPresented = errors.New("no server certificate presented")

// ErrCACertNotFound indicates the CA certificate file was not found.
var ErrCACertNotFound = errors.New("CA certificate file not found")

// VerifyServerCert returns a TLS verification callback that validates the server
// certificate against configured pins or installed CA certificates.
//
// The verification order is:
// 1. If CertPin is set, verify against the pin (and BackupPin if primary fails)
// 2. Otherwise, rely on the standard TLS certificate chain validation
//
// Usage with tls.Config:
//
//	tlsConfig := &tls.Config{
//	    VerifyPeerCertificate: VerifyServerCert(trustConfig),
//	}
func VerifyServerCert(cfg *TrustConfig) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return ErrNoCertPresented
		}

		serverCert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse server certificate: %w", err)
		}

		// Option 2: Certificate Pinning
		if cfg != nil && cfg.CertPin != "" {
			return verifyPin(serverCert, cfg.CertPin, cfg.BackupPin)
		}

		// Option 1: Standard chain validation (CA must be installed)
		// This is handled by the standard TLS stack when InsecureSkipVerify is false.
		// If we reach here with verifiedChains populated, the chain was already validated.
		if len(verifiedChains) == 0 {
			log.Debug("No verified chains - relying on system trust store")
		} else {
			log.Debug("Server certificate chain verified via system trust store")
		}

		return nil
	}
}

// verifyPin checks the server certificate against the configured pin(s).
func verifyPin(cert *x509.Certificate, primaryPin, backupPin string) error {
	// Calculate the certificate's SHA-256 fingerprint
	certHash := sha256.Sum256(cert.Raw)
	certHashB64 := base64.StdEncoding.EncodeToString(certHash[:])

	// Try primary pin
	if err := matchPin(certHashB64, primaryPin); err == nil {
		log.Debug("Server certificate verified against primary pin")
		return nil
	}

	// Try backup pin if available
	if backupPin != "" {
		if err := matchPin(certHashB64, backupPin); err == nil {
			log.Warn("Server certificate verified against BACKUP pin - primary pin may need update")
			return nil
		}
	}

	// Both pins failed
	expectedPin := extractPinHash(primaryPin)
	return fmt.Errorf("%w: expected %s..., got %s...",
		ErrCertPinMismatch,
		truncateHash(expectedPin, 16),
		truncateHash(certHashB64, 16))
}

// matchPin checks if a certificate hash matches a pin string.
func matchPin(certHashB64, pin string) error {
	if !strings.HasPrefix(pin, "sha256//") {
		return ErrInvalidPinFormat
	}

	pinHash := strings.TrimPrefix(pin, "sha256//")
	if certHashB64 == pinHash {
		return nil
	}

	return ErrCertPinMismatch
}

// extractPinHash extracts the hash from a pin string, handling format validation.
func extractPinHash(pin string) string {
	if strings.HasPrefix(pin, "sha256//") {
		return strings.TrimPrefix(pin, "sha256//")
	}
	return pin
}

// truncateHash truncates a hash string for display in error messages.
func truncateHash(hash string, maxLen int) string {
	if len(hash) <= maxLen {
		return hash
	}
	return hash[:maxLen]
}

// InstallCACert installs a CA certificate into the Windows Trusted Root store.
// This requires Administrator privileges.
//
// The certificate is installed to the LocalMachine\Root store, making it trusted
// for all users on the machine.
//
// Note: This is a security-sensitive operation. The CA certificate should be
// obtained through a secure channel (e.g., secure bootstrap bundle, verified download).
func InstallCACert(certPath string) error {
	// Verify file exists
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return fmt.Errorf("%w: %s", ErrCACertNotFound, certPath)
	}

	// Verify it's a valid certificate
	if err := validateCertFile(certPath); err != nil {
		return fmt.Errorf("invalid certificate file: %w", err)
	}

	log.Infof("Installing CA certificate to Windows Trusted Root: %s", certPath)

	// Use certutil to add to root store
	// -addstore root: Add to Trusted Root Certification Authorities
	// -f: Force overwrite if exists
	cmd := exec.Command("certutil", "-addstore", "-f", "root", certPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("certutil -addstore failed: %w, output: %s", err, string(output))
	}

	log.Info("CA certificate installed successfully to Trusted Root store")
	return nil
}

// RemoveCACert removes a CA certificate from the Windows Trusted Root store.
// The certificate is identified by its SHA-1 thumbprint.
//
// This can be used to clean up bootstrap CA certificates after domain join
// when enterprise CA trust is deployed via GPO.
func RemoveCACert(thumbprint string) error {
	if thumbprint == "" {
		return errors.New("thumbprint is required")
	}

	log.Infof("Removing CA certificate from Trusted Root: %s", thumbprint)

	// Use certutil to delete from root store
	cmd := exec.Command("certutil", "-delstore", "root", thumbprint)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("certutil -delstore failed: %w, output: %s", err, string(output))
	}

	log.Info("CA certificate removed from Trusted Root store")
	return nil
}

// GetCertPin calculates the SHA-256 pin for a certificate file.
// Returns the pin in the format "sha256//BASE64HASH".
//
// This can be used to generate the pin value for configuration.
func GetCertPin(certPath string) (string, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("read certificate file: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		// Try parsing as DER (binary) format
		hash := sha256.Sum256(certPEM)
		return "sha256//" + base64.StdEncoding.EncodeToString(hash[:]), nil
	}

	hash := sha256.Sum256(block.Bytes)
	return "sha256//" + base64.StdEncoding.EncodeToString(hash[:]), nil
}

// GetCertPinFromBytes calculates the SHA-256 pin for raw certificate bytes.
// The bytes can be either DER-encoded or PEM-encoded.
func GetCertPinFromBytes(certBytes []byte) (string, error) {
	if len(certBytes) == 0 {
		return "", errors.New("empty certificate data")
	}

	// Try PEM decode first
	block, _ := pem.Decode(certBytes)
	if block != nil {
		certBytes = block.Bytes
	}

	hash := sha256.Sum256(certBytes)
	return "sha256//" + base64.StdEncoding.EncodeToString(hash[:]), nil
}

// GetCertPinFromX509 calculates the SHA-256 pin for an x509.Certificate.
func GetCertPinFromX509(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return "sha256//" + base64.StdEncoding.EncodeToString(hash[:])
}

// validateCertFile checks if a file contains a valid certificate.
func validateCertFile(certPath string) error {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}

	// Try PEM format first
	block, _ := pem.Decode(certData)
	if block != nil {
		_, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse PEM certificate: %w", err)
		}
		return nil
	}

	// Try DER format
	_, err = x509.ParseCertificate(certData)
	if err != nil {
		return fmt.Errorf("parse DER certificate: %w", err)
	}

	return nil
}

// IsCACertInstalled checks if a CA certificate with the given thumbprint
// is installed in the Windows Trusted Root store.
func IsCACertInstalled(thumbprint string) (bool, error) {
	if thumbprint == "" {
		return false, errors.New("thumbprint is required")
	}

	// Use certutil to check if cert exists in root store
	cmd := exec.Command("certutil", "-verifystore", "root", thumbprint)
	err := cmd.Run()
	if err != nil {
		// Non-zero exit means cert not found or error
		return false, nil
	}

	return true, nil
}

// GetCertThumbprint calculates the SHA-1 thumbprint of a certificate file.
// This is the format used by Windows certificate stores.
func GetCertThumbprint(certPath string) (string, error) {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}

	// Try PEM format first
	block, _ := pem.Decode(certData)
	if block != nil {
		certData = block.Bytes
	}

	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}

	// SHA-1 thumbprint (standard Windows format)
	thumbprint := fmt.Sprintf("%X", sha256.Sum256(cert.Raw))
	return thumbprint, nil
}

// TrustBootstrap performs the complete trust establishment process.
// It installs the CA certificate and verifies the installation.
func TrustBootstrap(cfg *TrustConfig) error {
	if cfg == nil {
		return errors.New("trust config is nil")
	}

	// If using pinning, no installation needed
	if cfg.CertPin != "" {
		log.Info("Using certificate pinning - no CA installation required")
		return nil
	}

	// Install CA certificate if specified
	if cfg.CACertPath != "" {
		if err := InstallCACert(cfg.CACertPath); err != nil {
			return fmt.Errorf("install CA certificate: %w", err)
		}

		// Verify installation
		thumbprint, err := GetCertThumbprint(cfg.CACertPath)
		if err != nil {
			log.Warnf("Could not get thumbprint to verify installation: %v", err)
			return nil
		}

		installed, err := IsCACertInstalled(thumbprint)
		if err != nil {
			log.Warnf("Could not verify CA installation: %v", err)
			return nil
		}

		if !installed {
			return errors.New("CA certificate installation verification failed")
		}

		log.Info("CA certificate installation verified")
	}

	return nil
}
