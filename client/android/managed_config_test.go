package android

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
)

func TestManagedConfig_NewIsEmpty(t *testing.T) {
	m := NewManagedConfig()
	if m.HasConfig() {
		t.Error("new ManagedConfig should not have config")
	}
	if m.HasSetupKey() {
		t.Error("new ManagedConfig should not have setup key")
	}
	if m.GetSetupKey() != "" {
		t.Error("new ManagedConfig setup key should be empty")
	}
}

func TestManagedConfig_SettersMarkHasConfig(t *testing.T) {
	tests := []struct {
		name   string
		setter func(*ManagedConfig)
	}{
		{"managementURL", func(m *ManagedConfig) { m.SetManagementURL("https://example.com") }},
		{"setupKey", func(m *ManagedConfig) { m.SetSetupKey("test-key") }},
		{"adminURL", func(m *ManagedConfig) { m.SetAdminURL("https://admin.example.com") }},
		{"preSharedKey", func(m *ManagedConfig) { m.SetPreSharedKey("psk123") }},
		{"rosenpassEnabled", func(m *ManagedConfig) { m.SetRosenpassEnabled(true) }},
		{"rosenpassPermissive", func(m *ManagedConfig) { m.SetRosenpassPermissive(true) }},
		{"disableAutoConnect", func(m *ManagedConfig) { m.SetDisableAutoConnect(true) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewManagedConfig()
			tt.setter(m)
			if !m.HasConfig() {
				t.Errorf("HasConfig() should be true after setting %s", tt.name)
			}
		})
	}
}

func TestManagedConfig_SetupKey(t *testing.T) {
	m := NewManagedConfig()
	m.SetSetupKey("my-setup-key")
	if !m.HasSetupKey() {
		t.Error("HasSetupKey() should be true")
	}
	if m.GetSetupKey() != "my-setup-key" {
		t.Errorf("GetSetupKey() = %q, want %q", m.GetSetupKey(), "my-setup-key")
	}
}

func TestManagedConfig_ApplyEmpty(t *testing.T) {
	m := NewManagedConfig()
	cfgFile := filepath.Join(t.TempDir(), "netbird.json")
	err := m.Apply(cfgFile)
	if err != nil {
		t.Fatalf("Apply on empty config should not error: %v", err)
	}
}

func TestManagedConfig_ApplyManagementURL(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "netbird.json")

	m := NewManagedConfig()
	m.SetManagementURL("https://custom.mgmt.example.com:443")
	err := m.Apply(cfgFile)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	cfg, err := profilemanager.ReadConfig(cfgFile)
	if err != nil {
		t.Fatalf("ReadConfig failed: %v", err)
	}
	if cfg.ManagementURL.String() != "https://custom.mgmt.example.com:443" {
		t.Errorf("ManagementURL = %q, want %q", cfg.ManagementURL.String(), "https://custom.mgmt.example.com:443")
	}
}

func TestManagedConfig_ApplyOverridesExisting(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "netbird.json")

	// Create initial config with default URL
	p := NewPreferences(cfgFile)
	p.SetManagementURL("https://original.example.com:443")
	if err := p.Commit(); err != nil {
		t.Fatalf("initial Commit failed: %v", err)
	}

	// Apply MDM config that overrides the URL
	m := NewManagedConfig()
	m.SetManagementURL("https://mdm-managed.example.com:443")
	m.SetRosenpassEnabled(true)
	err := m.Apply(cfgFile)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	cfg, err := profilemanager.ReadConfig(cfgFile)
	if err != nil {
		t.Fatalf("ReadConfig failed: %v", err)
	}
	if cfg.ManagementURL.String() != "https://mdm-managed.example.com:443" {
		t.Errorf("ManagementURL = %q, want %q", cfg.ManagementURL.String(), "https://mdm-managed.example.com:443")
	}
	if !cfg.RosenpassEnabled {
		t.Error("RosenpassEnabled should be true after MDM apply")
	}
}

func TestManagedConfig_ApplyPreSharedKey(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "netbird.json")

	m := NewManagedConfig()
	m.SetPreSharedKey("mdm-psk-value")
	err := m.Apply(cfgFile)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	cfg, err := profilemanager.ReadConfig(cfgFile)
	if err != nil {
		t.Fatalf("ReadConfig failed: %v", err)
	}
	if cfg.PreSharedKey != "mdm-psk-value" {
		t.Errorf("PreSharedKey = %q, want %q", cfg.PreSharedKey, "mdm-psk-value")
	}
}

func TestManagedConfig_SetupKeyNotWrittenToConfig(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "netbird.json")

	m := NewManagedConfig()
	m.SetSetupKey("secret-setup-key")
	m.SetManagementURL("https://example.com:443")
	err := m.Apply(cfgFile)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	// Verify via structured read that the config was written correctly
	cfg, err := profilemanager.ReadConfig(cfgFile)
	if err != nil {
		t.Fatalf("ReadConfig failed: %v", err)
	}
	if cfg.ManagementURL.String() != "https://example.com:443" {
		t.Errorf("ManagementURL = %q, want %q", cfg.ManagementURL.String(), "https://example.com:443")
	}

	// Verify via raw file bytes that the setup key string is NOT in the config file
	raw, err := os.ReadFile(cfgFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if bytes.Contains(raw, []byte("secret-setup-key")) {
		t.Error("setup key should not appear in the config file")
	}
}

func TestManagedConfig_EmptyPreSharedKeyIgnored(t *testing.T) {
	m := NewManagedConfig()
	m.SetPreSharedKey("")
	if m.preSharedKey != nil {
		t.Error("empty pre-shared key should not be set")
	}
	if m.HasConfig() {
		t.Error("HasConfig() should be false when only empty PSK was set")
	}
}

func TestManagedConfig_SetupKeyOnlyDoesNotCreateConfig(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "netbird.json")

	m := NewManagedConfig()
	m.SetSetupKey("some-key")
	err := m.Apply(cfgFile)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	// Config file should NOT have been created since setup key is not persisted
	if _, err := os.Stat(cfgFile); err == nil {
		t.Error("config file should not be created when only setup key is set")
	}
}

func TestManagedConfig_KeyConstants(t *testing.T) {
	if GetManagedConfigKeyManagementURL() != "managementUrl" {
		t.Errorf("unexpected key: %s", GetManagedConfigKeyManagementURL())
	}
	if GetManagedConfigKeySetupKey() != "setupKey" {
		t.Errorf("unexpected key: %s", GetManagedConfigKeySetupKey())
	}
	if GetManagedConfigKeyAdminURL() != "adminUrl" {
		t.Errorf("unexpected key: %s", GetManagedConfigKeyAdminURL())
	}
	if GetManagedConfigKeyPreSharedKey() != "preSharedKey" {
		t.Errorf("unexpected key: %s", GetManagedConfigKeyPreSharedKey())
	}
	if GetManagedConfigKeyRosenpassEnabled() != "rosenpassEnabled" {
		t.Errorf("unexpected key: %s", GetManagedConfigKeyRosenpassEnabled())
	}
	if GetManagedConfigKeyRosenpassPermissive() != "rosenpassPermissive" {
		t.Errorf("unexpected key: %s", GetManagedConfigKeyRosenpassPermissive())
	}
	if GetManagedConfigKeyDisableAutoConnect() != "disableAutoConnect" {
		t.Errorf("unexpected key: %s", GetManagedConfigKeyDisableAutoConnect())
	}
}
