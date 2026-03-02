//go:build windows

package cert

import (
	"crypto/sha1" //nolint:gosec // SHA-1 used for Windows certutil fingerprint matching
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// InstallCA adds a CA certificate to the Windows Root certificate store.
func InstallCA(caPEM []byte) error {
	tmpFile, err := writeTempPEM(caPEM)
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile)

	out, err := exec.Command("certutil", "-addstore", "-f", "Root", tmpFile).CombinedOutput()
	if err != nil {
		return fmt.Errorf("certutil -addstore: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// UninstallCA removes a CA certificate from the Windows Root certificate store.
func UninstallCA(caPEM []byte) error {
	fp, err := sha1Fingerprint(caPEM)
	if err != nil {
		return err
	}

	out, err := exec.Command("certutil", "-delstore", "Root", fp).CombinedOutput()
	if err != nil {
		return fmt.Errorf("certutil -delstore: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// IsCATrusted checks whether a CA certificate is in the Windows Root store.
func IsCATrusted(caPEM []byte) bool {
	tmpFile, err := writeTempPEM(caPEM)
	if err != nil {
		return false
	}
	defer os.Remove(tmpFile)

	err = exec.Command("certutil", "-verify", tmpFile).Run()
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
