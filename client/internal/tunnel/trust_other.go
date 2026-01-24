//go:build !windows
// +build !windows

// Package tunnel provides trust establishment for management server connections.
// This file provides stub implementations for non-Windows platforms.
package tunnel

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

// TrustConfig holds configuration for server certificate verification.
type TrustConfig struct {
	// CACertPath is the path to a CA certificate file.
	// On non-Windows platforms, this is used for reference only.
	CACertPath string `yaml:"management_ca_cert,omitempty" json:"management_ca_cert,omitempty"`

	// CertPin is a SHA-256 fingerprint of the server certificate or CA certificate.
	// Format: "sha256//BASE64HASH"
	CertPin string `yaml:"management_cert_pin,omitempty" json:"management_cert_pin,omitempty"`

	// BackupPin is an optional backup pin for certificate rotation.
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

// ErrNotSupported indicates the operation is not supported on this platform.
var ErrNotSupported = errors.New("operation not supported on this platform")

// VerifyServerCert returns a TLS verification callback that validates the server
// certificate against configured pins.
//
// On non-Windows platforms, only certificate pinning is supported.
// CA certificate installation requires platform-specific implementation.
func VerifyServerCert(cfg *TrustConfig) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return ErrNoCertPresented
		}

		serverCert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("parse server certificate: %w", err)
		}

		// Certificate Pinning (works on all platforms)
		if cfg != nil && cfg.CertPin != "" {
			return verifyPin(serverCert, cfg.CertPin, cfg.BackupPin)
		}

		// Standard chain validation (handled by TLS stack)
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

// extractPinHash extracts the hash from a pin string.
func extractPinHash(pin string) string {
	if strings.HasPrefix(pin, "sha256//") {
		return strings.TrimPrefix(pin, "sha256//")
	}
	return pin
}

// truncateHash truncates a hash string for display.
func truncateHash(hash string, maxLen int) string {
	if len(hash) <= maxLen {
		return hash
	}
	return hash[:maxLen]
}

// InstallCACert is not supported on non-Windows platforms.
// Use system-specific methods (e.g., update-ca-certificates on Linux).
func InstallCACert(certPath string) error {
	return fmt.Errorf("%w: CA certificate installation requires platform-specific implementation", ErrNotSupported)
}

// RemoveCACert is not supported on non-Windows platforms.
func RemoveCACert(thumbprint string) error {
	return fmt.Errorf("%w: CA certificate removal requires platform-specific implementation", ErrNotSupported)
}

// GetCertPin calculates the SHA-256 pin for a certificate file.
// Returns the pin in the format "sha256//BASE64HASH".
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
func GetCertPinFromBytes(certBytes []byte) (string, error) {
	if len(certBytes) == 0 {
		return "", errors.New("empty certificate data")
	}

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

// IsCACertInstalled is not supported on non-Windows platforms.
func IsCACertInstalled(thumbprint string) (bool, error) {
	return false, fmt.Errorf("%w: CA certificate verification requires platform-specific implementation", ErrNotSupported)
}

// GetCertThumbprint calculates the SHA-256 thumbprint of a certificate file.
func GetCertThumbprint(certPath string) (string, error) {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode(certData)
	if block != nil {
		certData = block.Bytes
	}

	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}

	thumbprint := fmt.Sprintf("%X", sha256.Sum256(cert.Raw))
	return thumbprint, nil
}

// TrustBootstrap performs trust establishment.
// On non-Windows platforms, only certificate pinning is fully supported.
func TrustBootstrap(cfg *TrustConfig) error {
	if cfg == nil {
		return errors.New("trust config is nil")
	}

	if cfg.CertPin != "" {
		log.Info("Using certificate pinning - no CA installation required")
		return nil
	}

	if cfg.CACertPath != "" {
		log.Warn("CA certificate installation not supported on this platform")
		log.Warn("Please install the CA certificate manually using system tools")
		return fmt.Errorf("%w: use certificate pinning instead", ErrNotSupported)
	}

	return nil
}
