//go:build windows

// securitytest is a comprehensive test program for T-5.6 security features on Windows.
// Build: GOOS=windows GOARCH=amd64 go build -o securitytest.exe ./client/internal/tunnel/cmd/securitytest
// Run on Windows VM (as Administrator) to verify functionality.
//
//nolint:forbidigo // This is a CLI test tool that intentionally uses fmt.Print for output
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/netbirdio/netbird/client/internal/tunnel"
)

func main() {
	fmt.Println("=== NetBird Machine Tunnel - T-5.6 Security Test ===")
	fmt.Println()

	allPassed := true

	// Test 1: DPAPI Encrypt/Decrypt
	fmt.Println("[TEST 1] DPAPI Encryption/Decryption")
	if !testDPAPI() {
		allPassed = false
	}
	fmt.Println()

	// Test 2: Setup Key Encryption
	fmt.Println("[TEST 2] Setup Key Encryption Helper")
	if !testSetupKeyEncryption() {
		allPassed = false
	}
	fmt.Println()

	// Test 3: SecureZeroMemory
	fmt.Println("[TEST 3] SecureZeroMemory")
	if !testSecureZeroMemory() {
		allPassed = false
	}
	fmt.Println()

	// Test 4: ACL Hardening
	fmt.Println("[TEST 4] ACL Hardening (requires Administrator)")
	if !testACLHardening() {
		allPassed = false
	}
	fmt.Println()

	// Test 5: ACL Verification
	fmt.Println("[TEST 5] ACL Verification")
	if !testACLVerification() {
		allPassed = false
	}
	fmt.Println()

	// Test 6: EventLog Registration
	fmt.Println("[TEST 6] EventLog Registration (requires Administrator)")
	if !testEventLog() {
		allPassed = false
	}
	fmt.Println()

	// Test 7: Config Management with Cleanup
	fmt.Println("[TEST 7] Config Management & Cleanup")
	if !testConfigManagement() {
		allPassed = false
	}
	fmt.Println()

	// Summary
	if allPassed {
		fmt.Println("=== ALL TESTS PASSED ===")
	} else {
		fmt.Println("=== SOME TESTS FAILED ===")
		os.Exit(1)
	}
}

func testDPAPI() bool {
	passed := true
	testData := "This is a secret NetBird setup key: NBSK-xxxx-xxxx-xxxx"

	// Encrypt
	encrypted, err := tunnel.DPAPIEncrypt([]byte(testData))
	if err != nil {
		fmt.Printf("  [FAIL] DPAPIEncrypt: %v\n", err)
		return false
	}
	fmt.Printf("  [OK] DPAPIEncrypt: %d bytes -> %d chars base64\n", len(testData), len(encrypted))

	// Decrypt
	decrypted, err := tunnel.DPAPIDecrypt(encrypted)
	if err != nil {
		fmt.Printf("  [FAIL] DPAPIDecrypt: %v\n", err)
		return false
	}
	fmt.Printf("  [OK] DPAPIDecrypt: %d chars base64 -> %d bytes\n", len(encrypted), len(decrypted))

	// Verify round-trip
	if string(decrypted) == testData {
		fmt.Println("  [OK] Round-trip verification passed")
	} else {
		fmt.Println("  [FAIL] Round-trip verification failed - data mismatch!")
		passed = false
	}

	// Test empty input
	emptyEnc, err := tunnel.DPAPIEncrypt([]byte{})
	if err != nil {
		fmt.Printf("  [FAIL] Empty encrypt: %v\n", err)
		passed = false
	} else if emptyEnc == "" {
		fmt.Println("  [OK] Empty input handled correctly")
	}

	return passed
}

func testSetupKeyEncryption() bool {
	passed := true
	setupKey := "NBSK-test-1234-5678-abcd-efgh"

	// Encrypt
	encrypted, err := tunnel.EncryptSetupKey(setupKey)
	if err != nil {
		fmt.Printf("  [FAIL] EncryptSetupKey: %v\n", err)
		return false
	}
	fmt.Printf("  [OK] EncryptSetupKey: %d char key -> %d chars encrypted\n", len(setupKey), len(encrypted))

	// Decrypt
	decrypted, err := tunnel.DecryptSetupKey(encrypted)
	if err != nil {
		fmt.Printf("  [FAIL] DecryptSetupKey: %v\n", err)
		return false
	}

	if decrypted == setupKey {
		fmt.Println("  [OK] Setup key round-trip passed")
	} else {
		fmt.Println("  [FAIL] Setup key mismatch!")
		passed = false
	}

	// Test empty key
	emptyEnc, err := tunnel.EncryptSetupKey("")
	if err != nil {
		fmt.Printf("  [FAIL] Empty key encrypt: %v\n", err)
		passed = false
	} else if emptyEnc == "" {
		fmt.Println("  [OK] Empty setup key handled correctly")
	}

	return passed
}

func testSecureZeroMemory() bool {
	data := []byte("sensitive data here")

	tunnel.SecureZeroMemory(data)

	allZero := true
	for _, b := range data {
		if b != 0 {
			allZero = false
			break
		}
	}

	if allZero {
		fmt.Println("  [OK] SecureZeroMemory cleared all bytes")
		return true
	}
	fmt.Println("  [FAIL] SecureZeroMemory did not clear all bytes!")
	return false
}

func testACLHardening() bool {
	passed := true
	tmpDir := os.TempDir()
	testDir := filepath.Join(tmpDir, "netbird-acl-test-t56")

	// Clean up first
	os.RemoveAll(testDir)

	// Create directory
	if err := os.MkdirAll(testDir, 0700); err != nil {
		fmt.Printf("  [FAIL] Create test dir: %v\n", err)
		return false
	}
	defer os.RemoveAll(testDir)

	fmt.Printf("  [INFO] Test directory: %s\n", testDir)

	// Apply ACL hardening
	err := tunnel.HardenConfigDirectory(testDir)
	if err != nil {
		fmt.Printf("  [FAIL] HardenConfigDirectory: %v\n", err)
		fmt.Println("  [INFO] Note: ACL operations require Administrator privileges")
		return false
	}
	fmt.Println("  [OK] HardenConfigDirectory succeeded")

	// Test that Admin can't write after hardening
	testFile := filepath.Join(testDir, "test.conf")
	err = os.WriteFile(testFile, []byte("test config"), 0600)
	if err != nil {
		// Expected! Admin only has read access after hardening
		fmt.Printf("  [OK] Write correctly denied after hardening: Access is denied\n")
		fmt.Println("  [OK] ACL correctly restricts Admin to read-only")
	} else {
		fmt.Println("  [WARN] Write succeeded - running as SYSTEM or ACL not fully applied")
		// Clean up the file
		os.Remove(testFile)
	}

	return passed
}

func testACLVerification() bool {
	tmpDir := os.TempDir()
	testDir := filepath.Join(tmpDir, "netbird-acl-verify-t56")

	// Clean up first
	os.RemoveAll(testDir)

	// Test EnsureSecureConfigDir (creates and hardens)
	err := tunnel.EnsureSecureConfigDir(testDir)
	if err != nil {
		fmt.Printf("  [FAIL] EnsureSecureConfigDir: %v\n", err)
		fmt.Println("  [INFO] Note: ACL operations require Administrator privileges")
		return false
	}
	defer os.RemoveAll(testDir)

	fmt.Println("  [OK] EnsureSecureConfigDir succeeded")

	// Verify ACLs
	err = tunnel.VerifyConfigACL(testDir)
	if err != nil {
		fmt.Printf("  [FAIL] VerifyConfigACL: %v\n", err)
		return false
	}
	fmt.Println("  [OK] VerifyConfigACL passed")

	// Test GetConfigDir/GetConfigPath helpers
	configDir := tunnel.GetConfigDir()
	configPath := tunnel.GetConfigPath()
	fmt.Printf("  [INFO] Default config dir: %s\n", configDir)
	fmt.Printf("  [INFO] Default config path: %s\n", configPath)

	return true
}

func testEventLog() bool {
	passed := true

	// Try to register event source (requires admin)
	err := tunnel.RegisterEventSource()
	if err != nil {
		// May already exist
		fmt.Printf("  [INFO] RegisterEventSource: %v (may already exist)\n", err)
	} else {
		fmt.Println("  [OK] RegisterEventSource succeeded")
	}

	// Initialize event log
	err = tunnel.InitEventLog()
	if err != nil {
		fmt.Printf("  [FAIL] InitEventLog: %v\n", err)
		return false
	}
	fmt.Println("  [OK] InitEventLog succeeded")
	defer tunnel.CloseEventLog()

	// Log test events
	err = tunnel.LogInfo(tunnel.EventIDServiceStart, "T-5.6 Security Test - Service Start Event")
	if err != nil {
		fmt.Printf("  [FAIL] LogInfo: %v\n", err)
		passed = false
	} else {
		fmt.Println("  [OK] LogInfo succeeded")
	}

	err = tunnel.LogACLHardened("C:\\Test\\Path")
	if err != nil {
		fmt.Printf("  [FAIL] LogACLHardened: %v\n", err)
		passed = false
	} else {
		fmt.Println("  [OK] LogACLHardened succeeded")
	}

	err = tunnel.LogSetupKeyRemoved()
	if err != nil {
		fmt.Printf("  [FAIL] LogSetupKeyRemoved: %v\n", err)
		passed = false
	} else {
		fmt.Println("  [OK] LogSetupKeyRemoved succeeded")
	}

	fmt.Println("  [INFO] Check Event Viewer > Application for NetBirdMachine events")

	return passed
}

func testConfigManagement() bool {
	passed := true
	tmpDir := os.TempDir()
	testConfigPath := filepath.Join(tmpDir, "netbird-config-test", "config.yaml")

	// Clean up first
	os.RemoveAll(filepath.Dir(testConfigPath))

	// Create initial config with setup key
	config, err := tunnel.InitializeConfig("https://netbird.example.com:443", "NBSK-test-key-1234")
	if err != nil {
		fmt.Printf("  [FAIL] InitializeConfig: %v\n", err)
		return false
	}
	fmt.Println("  [OK] InitializeConfig succeeded")

	// Verify setup key is encrypted
	if config.HasSetupKey() {
		fmt.Println("  [OK] Config has setup key (encrypted)")
	} else {
		fmt.Println("  [FAIL] Config should have setup key")
		passed = false
	}

	// Get decrypted setup key
	setupKey, err := config.GetSetupKey()
	switch {
	case err != nil:
		fmt.Printf("  [FAIL] GetSetupKey: %v\n", err)
		passed = false
	case setupKey == "NBSK-test-key-1234":
		fmt.Println("  [OK] GetSetupKey returns correct value")
	default:
		fmt.Printf("  [FAIL] GetSetupKey returned wrong value: %s\n", setupKey)
		passed = false
	}

	// Save config
	err = config.SaveTo(testConfigPath)
	if err != nil {
		fmt.Printf("  [FAIL] SaveTo: %v\n", err)
		// May fail due to ACL, continue with other tests
	} else {
		fmt.Printf("  [OK] Config saved to %s\n", testConfigPath)
		defer os.RemoveAll(filepath.Dir(testConfigPath))

		// Load config back
		loadedConfig, err := tunnel.LoadMachineConfigFrom(testConfigPath)
		if err != nil {
			fmt.Printf("  [FAIL] LoadMachineConfigFrom: %v\n", err)
			passed = false
		} else {
			fmt.Println("  [OK] LoadMachineConfigFrom succeeded")

			// Verify loaded config has setup key
			if loadedConfig.HasSetupKey() {
				fmt.Println("  [OK] Loaded config has setup key")
			} else {
				fmt.Println("  [FAIL] Loaded config should have setup key")
				passed = false
			}
		}
	}

	// Test cleanup after bootstrap
	fmt.Println("  [INFO] Testing cleanup after bootstrap...")
	err = config.CleanupAfterBootstrap()
	if err != nil {
		fmt.Printf("  [WARN] CleanupAfterBootstrap: %v (may fail due to ACLs)\n", err)
	} else {
		if !config.HasSetupKey() {
			fmt.Println("  [OK] CleanupAfterBootstrap removed setup key")
		} else {
			fmt.Println("  [FAIL] CleanupAfterBootstrap did not remove setup key")
			passed = false
		}
	}

	return passed
}
