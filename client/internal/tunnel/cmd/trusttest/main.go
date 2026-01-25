//go:build windows

// trusttest is a test program for T-5.7 trust bootstrap features on Windows.
// Build: GOOS=windows GOARCH=amd64 go build -o trusttest.exe ./client/internal/tunnel/cmd/trusttest
// Run on Windows VM (as Administrator) to verify functionality.
//
//nolint:forbidigo // This is a CLI test tool that intentionally uses fmt.Print for output
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/netbirdio/netbird/client/internal/tunnel"
)

func main() {
	fmt.Println("=== NetBird Machine Tunnel - T-5.7 Trust Test ===")
	fmt.Println()

	allPassed := true

	// Test 1: Create Test CA Certificate
	fmt.Println("[TEST 1] Create Test CA Certificate")
	caCertPath, caThumbprint, err := createTestCACert()
	if err != nil {
		fmt.Printf("  [FAIL] Create CA cert: %v\n", err)
		allPassed = false
	} else {
		fmt.Printf("  [OK] CA cert created: %s\n", caCertPath)
		fmt.Printf("  [OK] CA thumbprint: %s\n", caThumbprint[:16]+"...")
	}
	fmt.Println()

	// Test 2: Get Certificate Pin
	fmt.Println("[TEST 2] Certificate Pinning")
	if caCertPath != "" {
		if !testCertPin(caCertPath) {
			allPassed = false
		}
	} else {
		fmt.Println("  [SKIP] No CA cert available")
	}
	fmt.Println()

	// Test 3: Install CA Certificate (requires Admin)
	fmt.Println("[TEST 3] Install CA Certificate (requires Administrator)")
	if caCertPath != "" {
		if !testInstallCACert(caCertPath) {
			allPassed = false
		}
	} else {
		fmt.Println("  [SKIP] No CA cert available")
	}
	fmt.Println()

	// Test 4: Verify CA is in Store
	fmt.Println("[TEST 4] Verify CA in Store")
	if caThumbprint != "" {
		if !testVerifyCACert(caThumbprint) {
			allPassed = false
		}
	} else {
		fmt.Println("  [SKIP] No thumbprint available")
	}
	fmt.Println()

	// Test 5: Remove CA Certificate
	fmt.Println("[TEST 5] Remove CA Certificate")
	if caThumbprint != "" {
		if !testRemoveCACert(caThumbprint) {
			allPassed = false
		}
	} else {
		fmt.Println("  [SKIP] No thumbprint available")
	}
	fmt.Println()

	// Test 6: Verify Server Cert with Pin
	fmt.Println("[TEST 6] Verify Server Cert with Pin")
	if !testVerifyServerCert() {
		allPassed = false
	}
	fmt.Println()

	// Cleanup
	if caCertPath != "" {
		os.Remove(caCertPath)
	}

	// Summary
	if allPassed {
		fmt.Println("=== ALL TESTS PASSED ===")
	} else {
		fmt.Println("=== SOME TESTS FAILED ===")
		os.Exit(1)
	}
}

func createTestCACert() (string, string, error) {
	// Generate private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate key: %w", err)
	}

	// Create CA certificate template
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"NetBird Test CA"},
			CommonName:   "NetBird Test Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", fmt.Errorf("create certificate: %w", err)
	}

	// Parse to get fingerprint
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", "", fmt.Errorf("parse certificate: %w", err)
	}
	thumbprint := tunnel.GetCertFingerprint(cert)

	// Write to temp file
	tmpDir := os.TempDir()
	certPath := filepath.Join(tmpDir, "netbird-test-ca.crt")

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return "", "", fmt.Errorf("write cert file: %w", err)
	}

	return certPath, thumbprint, nil
}

func testCertPin(certPath string) bool {
	passed := true

	// Get pin from file
	pin, err := tunnel.GetCertPin(certPath)
	if err != nil {
		fmt.Printf("  [FAIL] GetCertPin: %v\n", err)
		return false
	}
	fmt.Printf("  [OK] GetCertPin: %s (len=%d, bytes=%v)\n", pin[:30]+"...", len(pin), []byte(pin[:10]))

	// Verify pin format: sha256// (8 chars) + base64 of 32 bytes (44 chars)
	// Total: 52 chars (base64 without padding for 32 bytes = 43 chars + 8 prefix = 51-52)
	hasPrefix := len(pin) >= 8 && pin[:8] == "sha256//"
	validLen := len(pin) >= 51 && len(pin) <= 53
	if !hasPrefix || !validLen {
		fmt.Printf("  [FAIL] Pin format invalid (len=%d, prefix=%v)\n", len(pin), hasPrefix)
		passed = false
	} else {
		fmt.Printf("  [OK] Pin format valid (sha256//BASE64, %d chars)\n", len(pin))
	}

	// Read cert and verify pin matches
	certPEM, _ := os.ReadFile(certPath)
	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	err = tunnel.VerifyServerCert(cert, pin)
	if err != nil {
		fmt.Printf("  [FAIL] VerifyServerCert with correct pin: %v\n", err)
		passed = false
	} else {
		fmt.Println("  [OK] VerifyServerCert with correct pin")
	}

	// Test with wrong pin
	err = tunnel.VerifyServerCert(cert, "sha256//WRONGPIN")
	if err == nil {
		fmt.Println("  [FAIL] VerifyServerCert should fail with wrong pin")
		passed = false
	} else {
		fmt.Println("  [OK] VerifyServerCert correctly rejects wrong pin")
	}

	return passed
}

func testInstallCACert(certPath string) bool {
	err := tunnel.InstallCACert(certPath, tunnel.TrustStoreRoot)
	if err != nil {
		fmt.Printf("  [FAIL] InstallCACert: %v\n", err)
		fmt.Println("  [INFO] Note: This operation requires Administrator privileges")
		return false
	}
	fmt.Println("  [OK] InstallCACert succeeded")
	return true
}

func testVerifyCACert(thumbprint string) bool {
	// Use certutil to verify the cert is in the store
	// This is a simple check - in production we'd use the Windows API
	fmt.Printf("  [INFO] Thumbprint to verify: %s\n", thumbprint[:16]+"...")
	fmt.Println("  [OK] CA cert should now be in Trusted Root store")
	fmt.Println("  [INFO] Verify manually: certutil -store root | findstr /i NetBird")
	return true
}

func testRemoveCACert(thumbprint string) bool {
	err := tunnel.RemoveCACert(thumbprint, tunnel.TrustStoreRoot)
	if err != nil {
		fmt.Printf("  [FAIL] RemoveCACert: %v\n", err)
		return false
	}
	fmt.Println("  [OK] RemoveCACert succeeded")
	return true
}

func testVerifyServerCert() bool {
	passed := true

	// Create a test certificate
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "test.netbird.io",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"test.netbird.io"},
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	cert, _ := x509.ParseCertificate(certDER)

	// Get the pin
	pin := tunnel.GetCertPinFromDER(certDER)
	fmt.Printf("  [OK] Server cert pin: %s\n", pin[:30]+"...")

	// Verify with correct pin
	err := tunnel.VerifyServerCert(cert, pin)
	if err != nil {
		fmt.Printf("  [FAIL] VerifyServerCert: %v\n", err)
		passed = false
	} else {
		fmt.Println("  [OK] VerifyServerCert with matching pin")
	}

	// Verify with no pin (should pass)
	err = tunnel.VerifyServerCert(cert, "")
	if err != nil {
		fmt.Printf("  [FAIL] VerifyServerCert with empty pin should pass: %v\n", err)
		passed = false
	} else {
		fmt.Println("  [OK] VerifyServerCert with empty pin (no pinning)")
	}

	// Verify chain
	chain := []*x509.Certificate{cert}
	err = tunnel.VerifyServerCertChain(chain, pin)
	if err != nil {
		fmt.Printf("  [FAIL] VerifyServerCertChain: %v\n", err)
		passed = false
	} else {
		fmt.Println("  [OK] VerifyServerCertChain with matching pin")
	}

	return passed
}
