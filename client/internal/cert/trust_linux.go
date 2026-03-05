//go:build linux

package cert

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
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

	certPath := fmt.Sprintf("%s/netbird-%s.crt", certDir, fp)
	if err := os.WriteFile(certPath, caPEM, 0644); err != nil {
		return fmt.Errorf("write CA cert: %w", err)
	}

	if err := runWithTimeout(updateCmd, 30*time.Second); err != nil {
		return err
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

	certPath := fmt.Sprintf("%s/netbird-%s.crt", certDir, fp)
	if err := os.Remove(certPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove CA cert: %w", err)
	}

	if err := runWithTimeout(updateCmd, 30*time.Second); err != nil {
		return err
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

	certPath := fmt.Sprintf("%s/netbird-%s.crt", certDir, fp)
	_, err = os.Stat(certPath)
	return err == nil
}

// resolveCmd tries known absolute paths before falling back to LookPath,
// which may fail in restricted daemon/service environments where /usr/sbin
// is not in PATH.
func resolveCmd(name string) (string, error) {
	candidates := []string{
		"/usr/sbin/" + name,
		"/usr/bin/" + name,
		"/sbin/" + name,
		"/bin/" + name,
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && st.Mode().Perm()&0111 != 0 {
			return p, nil
		}
	}
	return exec.LookPath(name)
}

func detectDistro() (certDir, updateCmd string, err error) {
	if _, err := os.Stat(debianCertDir); err == nil {
		if cmd, err := resolveCmd(debianUpdateCmd); err == nil {
			return debianCertDir, cmd, nil
		}
	}
	if _, err := os.Stat(rhelCertDir); err == nil {
		if cmd, err := resolveCmd(rhelUpdateCmd); err == nil {
			return rhelCertDir, cmd, nil
		}
	}
	return "", "", fmt.Errorf("unsupported Linux distribution: neither %s nor %s found", debianUpdateCmd, rhelUpdateCmd)
}

func runWithTimeout(command string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, command).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s: %w", command, strings.TrimSpace(string(out)), err)
	}
	return nil
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
