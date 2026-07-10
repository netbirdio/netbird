package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestApplySimplifiedDefaultsWithAdditionalRelays(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.ExposedAddress = "https://netbird.example.com:443"
	cfg.Server.AuthSecret = "shared-relay-secret"
	cfg.Server.AdditionalRelays = []string{
		"rels://relay-eu.example.com:443",
		"rels://relay-us.example.com:443",
	}

	cfg.ApplySimplifiedDefaults()

	if !cfg.Relay.Enabled {
		t.Fatal("local relay should remain enabled when additional relays are configured")
	}
	if !cfg.Relay.Stun.Enabled {
		t.Fatal("local STUN should remain enabled when additional relays are configured")
	}

	wantAddresses := []string{
		"rels://netbird.example.com:443",
		"rels://relay-eu.example.com:443",
		"rels://relay-us.example.com:443",
	}
	if !reflect.DeepEqual(cfg.Management.Relays.Addresses, wantAddresses) {
		t.Fatalf("relay addresses = %v, want %v", cfg.Management.Relays.Addresses, wantAddresses)
	}
	if cfg.Management.Relays.Secret != cfg.Server.AuthSecret {
		t.Fatalf("relay secret = %q, want server auth secret", cfg.Management.Relays.Secret)
	}
}

func TestApplySimplifiedDefaultsWithRelayOverride(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.ExposedAddress = "https://netbird.example.com:443"
	cfg.Server.Relays = RelaysConfig{
		Addresses:      []string{"rels://relay.example.com:443"},
		CredentialsTTL: "24h",
		Secret:         "external-relay-secret",
	}

	cfg.ApplySimplifiedDefaults()

	if cfg.Relay.Enabled {
		t.Fatal("local relay should remain disabled when server.relays overrides it")
	}
	if cfg.Relay.Stun.Enabled {
		t.Fatal("local STUN should remain disabled with the relay override")
	}
	if !reflect.DeepEqual(cfg.Management.Relays, cfg.Server.Relays) {
		t.Fatalf("management relay config = %+v, want %+v", cfg.Management.Relays, cfg.Server.Relays)
	}
}

func TestAdditionalRelaysStillRequireLocalRelaySecret(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Server.ExposedAddress = "https://netbird.example.com:443"
	cfg.Server.AuthSecret = ""
	cfg.Server.AdditionalRelays = []string{"rels://relay.example.com:443"}

	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() should require server.authSecret because the local relay is enabled")
	}
}

func TestLoadConfigParsesAdditionalRelays(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	configData := []byte(`server:
  exposedAddress: "https://netbird.example.com:443"
  authSecret: "shared-relay-secret"
  additionalRelays:
    - "rels://relay-eu.example.com:443"
    - "rels://relay-us.example.com:443"
`)
	if err := os.WriteFile(configPath, configData, 0o600); err != nil {
		t.Fatalf("write test config: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	wantAddresses := []string{
		"rels://netbird.example.com:443",
		"rels://relay-eu.example.com:443",
		"rels://relay-us.example.com:443",
	}
	if !reflect.DeepEqual(cfg.Management.Relays.Addresses, wantAddresses) {
		t.Fatalf("relay addresses = %v, want %v", cfg.Management.Relays.Addresses, wantAddresses)
	}
}
