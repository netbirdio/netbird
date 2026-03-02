//go:build darwin

package cert

import (
	"crypto/sha1" //nolint:gosec // SHA-1 used for macOS Keychain fingerprint matching
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// InstallCA adds a CA certificate to the macOS System Keychain as a trusted root.
func InstallCA(caPEM []byte) error {
	tmpFile, err := writeTempPEM(caPEM)
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile)

	out, err := exec.Command("security", "add-trusted-cert", "-d", "-r", "trustRoot",
		"-k", "/Library/Keychains/System.keychain", tmpFile).CombinedOutput()
	if err != nil {
		return fmt.Errorf("security add-trusted-cert: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// UninstallCA removes a CA certificate from the macOS System Keychain by its SHA-1 fingerprint.
func UninstallCA(caPEM []byte) error {
	fp, err := sha1Fingerprint(caPEM)
	if err != nil {
		return err
	}

	out, err := exec.Command("security", "delete-certificate", "-Z", fp,
		"/Library/Keychains/System.keychain").CombinedOutput()
	if err != nil {
		return fmt.Errorf("security delete-certificate: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// IsCATrusted checks whether a CA certificate is trusted by the macOS system.
func IsCATrusted(caPEM []byte) bool {
	tmpFile, err := writeTempPEM(caPEM)
	if err != nil {
		return false
	}
	defer os.Remove(tmpFile)

	err = exec.Command("security", "verify-cert", "-c", tmpFile).Run()
	return err == nil
}

func writeTempPEM(data []byte) (string, error) {
	f, err := os.CreateTemp("", "netbird-ca-*.pem")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", fmt.Errorf("write temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("close temp file: %w", err)
	}
	return f.Name(), nil
}

func sha1Fingerprint(caPEM []byte) (string, error) {
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return "", fmt.Errorf("no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}
	sum := sha1.Sum(cert.Raw) //nolint:gosec
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
}
