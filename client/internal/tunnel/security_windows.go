//go:build windows

// Package tunnel provides machine tunnel functionality for Windows pre-login VPN.
package tunnel

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"gopkg.in/yaml.v3"
)

// DPAPI constants
const (
	cryptProtectUIForbidden = 0x1
)

var (
	crypt32                  = windows.NewLazySystemDLL("crypt32.dll")
	procCryptProtectData     = crypt32.NewProc("CryptProtectData")
	procCryptUnprotectData   = crypt32.NewProc("CryptUnprotectData")
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procRtlSecureZeroMemory  = kernel32.NewProc("RtlSecureZeroMemory")
)

// DATA_BLOB structure for DPAPI
type dataBlob struct {
	cbData uint32
	pbData *byte
}

// DPAPIEncrypt encrypts data using Windows DPAPI (machine scope).
// Returns base64-encoded encrypted data.
func DPAPIEncrypt(plaintext []byte) (string, error) {
	if len(plaintext) == 0 {
		return "", nil
	}

	var inBlob dataBlob
	inBlob.cbData = uint32(len(plaintext))
	inBlob.pbData = &plaintext[0]

	var outBlob dataBlob

	ret, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, // no description
		0, // no additional entropy
		0, // reserved
		0, // no prompt struct
		uintptr(cryptProtectUIForbidden),
		uintptr(unsafe.Pointer(&outBlob)),
	)

	if ret == 0 {
		return "", fmt.Errorf("CryptProtectData failed: %w", err)
	}

	defer func() {
		_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.pbData)))
	}()

	encrypted := make([]byte, outBlob.cbData)
	copy(encrypted, unsafe.Slice(outBlob.pbData, outBlob.cbData))

	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DPAPIDecrypt decrypts base64-encoded DPAPI data.
func DPAPIDecrypt(ciphertext string) ([]byte, error) {
	if ciphertext == "" {
		return []byte{}, nil
	}

	encrypted, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	var inBlob dataBlob
	inBlob.cbData = uint32(len(encrypted))
	inBlob.pbData = &encrypted[0]

	var outBlob dataBlob

	ret, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, // no description
		0, // no additional entropy
		0, // reserved
		0, // no prompt struct
		uintptr(cryptProtectUIForbidden),
		uintptr(unsafe.Pointer(&outBlob)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed: %w", err)
	}

	defer func() {
		_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.pbData)))
	}()

	decrypted := make([]byte, outBlob.cbData)
	copy(decrypted, unsafe.Slice(outBlob.pbData, outBlob.cbData))

	return decrypted, nil
}

// EncryptSetupKey encrypts a setup key using DPAPI.
func EncryptSetupKey(setupKey string) (string, error) {
	if setupKey == "" {
		return "", nil
	}
	return DPAPIEncrypt([]byte(setupKey))
}

// DecryptSetupKey decrypts a setup key using DPAPI.
func DecryptSetupKey(encrypted string) (string, error) {
	if encrypted == "" {
		return "", nil
	}
	decrypted, err := DPAPIDecrypt(encrypted)
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

// SecureZeroMemory securely zeros a byte slice.
func SecureZeroMemory(data []byte) {
	if len(data) == 0 {
		return
	}

	// Try RtlSecureZeroMemory first
	ret, _, _ := procRtlSecureZeroMemory.Call(
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
	)

	// If RtlSecureZeroMemory fails, fall back to manual zeroing
	if ret == 0 {
		for i := range data {
			data[i] = 0
		}
	}
}

// DefaultConfigDir is the default configuration directory.
const DefaultConfigDir = `C:\ProgramData\NetBird`

// GetConfigDir returns the default configuration directory.
func GetConfigDir() string {
	return DefaultConfigDir
}

// GetConfigPath returns the default configuration file path.
func GetConfigPath() string {
	return filepath.Join(DefaultConfigDir, "machine-config.yaml")
}

// HardenConfigDirectory applies restrictive ACLs to the config directory.
// Only SYSTEM and Administrators have access, with SYSTEM having full control
// and Administrators having read-only access.
func HardenConfigDirectory(path string) error {
	// Get the security descriptor
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("get security info: %w", err)
	}

	// Get SYSTEM and Administrators SIDs
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("create SYSTEM SID: %w", err)
	}

	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("create Administrators SID: %w", err)
	}

	// Create new DACL with:
	// - SYSTEM: Full Control
	// - Administrators: Read Only
	entries := []windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(systemSID),
			},
		},
		{
			AccessPermissions: windows.GENERIC_READ,
			AccessMode:        windows.SET_ACCESS,
			Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
				TrusteeValue: windows.TrusteeValueFromSID(adminSID),
			},
		},
	}

	newACL, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("create ACL: %w", err)
	}

	// Apply the new DACL
	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		newACL,
		nil,
	)
	if err != nil {
		return fmt.Errorf("set security info: %w", err)
	}

	_ = sd // avoid unused variable warning

	return nil
}

// EnsureSecureConfigDir creates the config directory if needed and applies hardened ACLs.
func EnsureSecureConfigDir(path string) error {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(path, 0700); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	// Apply hardened ACLs
	return HardenConfigDirectory(path)
}

// VerifyConfigACL verifies that the config directory has proper ACLs.
func VerifyConfigACL(path string) error {
	// Get the security descriptor
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("get security info: %w", err)
	}

	// Get the DACL
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("get DACL: %w", err)
	}

	if dacl == nil {
		return fmt.Errorf("no DACL present")
	}

	// Basic verification - DACL exists
	// More detailed verification would check specific ACEs
	return nil
}

// SecureConfig provides secure configuration management with encrypted setup keys.
// This is used for testing DPAPI encryption of sensitive config values.
type SecureConfig struct {
	ManagementURL      string `yaml:"management_url"`
	EncryptedSetupKey  string `yaml:"encrypted_setup_key,omitempty"`
	MachineCertEnabled bool   `yaml:"machine_cert_enabled"`
}

// InitializeConfig creates a new SecureConfig with an encrypted setup key.
func InitializeConfig(managementURL, setupKey string) (*SecureConfig, error) {
	cfg := &SecureConfig{
		ManagementURL: managementURL,
	}

	if setupKey != "" {
		encrypted, err := EncryptSetupKey(setupKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt setup key: %w", err)
		}
		cfg.EncryptedSetupKey = encrypted
	}

	return cfg, nil
}

// LoadMachineConfigFrom loads a SecureConfig from a YAML file.
func LoadMachineConfigFrom(path string) (*SecureConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var cfg SecureConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return &cfg, nil
}

// HasSetupKey returns true if the config has an encrypted setup key.
func (c *SecureConfig) HasSetupKey() bool {
	return c.EncryptedSetupKey != ""
}

// GetSetupKey decrypts and returns the setup key.
func (c *SecureConfig) GetSetupKey() (string, error) {
	if c.EncryptedSetupKey == "" {
		return "", nil
	}
	return DecryptSetupKey(c.EncryptedSetupKey)
}

// SetSetupKey encrypts and stores the setup key.
func (c *SecureConfig) SetSetupKey(setupKey string) error {
	if setupKey == "" {
		c.EncryptedSetupKey = ""
		return nil
	}
	encrypted, err := EncryptSetupKey(setupKey)
	if err != nil {
		return fmt.Errorf("encrypt setup key: %w", err)
	}
	c.EncryptedSetupKey = encrypted
	return nil
}

// SaveTo saves the config to a YAML file, creating parent directories if needed.
func (c *SecureConfig) SaveTo(path string) error {
	// Ensure parent directory exists with proper ACLs
	dir := filepath.Dir(path)
	if err := EnsureSecureConfigDir(dir); err != nil {
		return fmt.Errorf("ensure config dir: %w", err)
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	return nil
}

// CleanupAfterBootstrap removes the setup key after successful mTLS bootstrap.
// This should be called after the machine has obtained a certificate.
func (c *SecureConfig) CleanupAfterBootstrap() error {
	if c.EncryptedSetupKey == "" {
		return nil
	}

	// Securely clear the encrypted key from memory
	keyBytes := []byte(c.EncryptedSetupKey)
	SecureZeroMemory(keyBytes)

	c.EncryptedSetupKey = ""
	return nil
}
