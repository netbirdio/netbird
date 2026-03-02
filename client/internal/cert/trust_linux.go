//go:build linux

package cert

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	// Debian/Ubuntu paths
	debianCertDir    = "/usr/local/share/ca-certificates"
	debianUpdateCmd  = "update-ca-certificates"

	// RHEL/Fedora paths
	rhelCertDir   = "/etc/pki/ca-trust/source/anchors"
	rhelUpdateCmd = "update-ca-trust"
)

// InstallCA adds a CA certificate to the Linux system trust store.
// Supports Debian/Ubuntu and RHEL/Fedora families.
func InstallCA(caPEM []byte) error {
	certDir, updateCmd, err := detectDistro()
	if err != nil {
		return err
	}

	fp, err := certFingerprint(caPEM)
	if err != nil {
		return err
	}

	certPath := fmt.Sprintf("%s/netbird-%s.crt", certDir, fp[:16])
	if err := os.WriteFile(certPath, caPEM, 0644); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}

	out, err := exec.Command(updateCmd).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s: %w", updateCmd, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// UninstallCA removes a CA certificate from the Linux system trust store.
func UninstallCA(caPEM []byte) error {
	certDir, updateCmd, err := detectDistro()
	if err != nil {
		return err
	}

	fp, err := certFingerprint(caPEM)
	if err != nil {
		return err
	}

	certPath := fmt.Sprintf("%s/netbird-%s.crt", certDir, fp[:16])
	if err := os.Remove(certPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove CA cert: %w", err)
	}

	out, err := exec.Command(updateCmd).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s: %w", updateCmd, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// IsCATrusted checks whether a CA certificate file exists in the system trust store.
func IsCATrusted(caPEM []byte) bool {
	certDir, _, err := detectDistro()
	if err != nil {
		return false
	}

	fp, err := certFingerprint(caPEM)
	if err != nil {
		return false
	}

	certPath := fmt.Sprintf("%s/netbird-%s.crt", certDir, fp[:16])
	_, err = os.Stat(certPath)
	return err == nil
}

func detectDistro() (certDir, updateCmd string, err error) {
	if _, err := os.Stat(debianCertDir); err == nil {
		if _, err := exec.LookPath(debianUpdateCmd); err == nil {
			return debianCertDir, debianUpdateCmd, nil
		}
	}
	if _, err := os.Stat(rhelCertDir); err == nil {
		if _, err := exec.LookPath(rhelUpdateCmd); err == nil {
			return rhelCertDir, rhelUpdateCmd, nil
		}
	}
	return "", "", fmt.Errorf("unsupported Linux distribution: neither %s nor %s found", debianUpdateCmd, rhelUpdateCmd)
}

func certFingerprint(caPEM []byte) (string, error) {
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return "", fmt.Errorf("no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), nil
}
