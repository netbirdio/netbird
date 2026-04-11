//go:build windows

package server

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

const (
	// credProvDLLName is the filename of the credential provider DLL.
	credProvDLLName = "netbird_credprov.dll"
)

// RegisterCredentialProvider registers the NetBird Credential Provider COM DLL
// using regsvr32. The DLL must be shipped alongside the NetBird executable.
func RegisterCredentialProvider() error {
	dllPath, err := findCredProvDLL()
	if err != nil {
		return fmt.Errorf("find credential provider DLL: %w", err)
	}

	cmd := exec.Command("regsvr32", "/s", dllPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("regsvr32 %s: %w (output: %s)", dllPath, err, string(output))
	}

	log.Infof("registered RDP credential provider: %s", dllPath)
	return nil
}

// UnregisterCredentialProvider unregisters the NetBird Credential Provider COM DLL.
func UnregisterCredentialProvider() error {
	dllPath, err := findCredProvDLL()
	if err != nil {
		log.Debugf("credential provider DLL not found for unregistration: %v", err)
		return nil
	}

	cmd := exec.Command("regsvr32", "/s", "/u", dllPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("regsvr32 /u %s: %w (output: %s)", dllPath, err, string(output))
	}

	log.Infof("unregistered RDP credential provider: %s", dllPath)
	return nil
}

// findCredProvDLL locates the credential provider DLL next to the running executable.
func findCredProvDLL() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("get executable path: %w", err)
	}

	dllPath := filepath.Join(filepath.Dir(exePath), credProvDLLName)
	if _, err := os.Stat(dllPath); err != nil {
		return "", fmt.Errorf("DLL not found at %s: %w", dllPath, err)
	}

	return dllPath, nil
}
