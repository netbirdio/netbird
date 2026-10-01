package android

import (
	"path/filepath"
	"testing"
)

// NewAuth must reuse the configuration already at cfgPath rather than building a fresh one.
//
// Creating a new in-memory config on every call gives the client a new WireGuard private key each
// time. The peer registers under that key and the key is written out, so a peer registered by an
// earlier call is orphaned on the server — a client that enrols twice leaves two entries and owns
// neither. It also breaks enrol-then-run: RunWithoutLogin reloads the configuration from disk, so
// the identity that registered is not the identity that runs, and the management stream rejects it
// with "no peer auth method provided, please use a setup key or interactive SSO login".
func TestNewAuth_ReusesPersistedIdentity(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.json")

	first, err := NewAuth(cfgPath, "https://api.example.com:443", nil)
	if err != nil {
		t.Fatalf("first NewAuth: %v", err)
	}
	if first.config.PrivateKey == "" {
		t.Fatal("first NewAuth produced no private key")
	}

	second, err := NewAuth(cfgPath, "https://api.example.com:443", nil)
	if err != nil {
		t.Fatalf("second NewAuth: %v", err)
	}

	if second.config.PrivateKey != first.config.PrivateKey {
		t.Errorf("private key changed between calls: a second enrolment would orphan the peer registered by the first")
	}
}

// A missing configuration is still created, so a first enrolment works unchanged.
func TestNewAuth_CreatesConfigWhenAbsent(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.json")

	auth, err := NewAuth(cfgPath, "https://api.example.com:443", nil)
	if err != nil {
		t.Fatalf("NewAuth: %v", err)
	}
	if auth.config == nil || auth.config.PrivateKey == "" {
		t.Fatal("NewAuth did not create a usable configuration")
	}
	if auth.cfgPath != cfgPath {
		t.Errorf("cfgPath = %q, want %q", auth.cfgPath, cfgPath)
	}
}
