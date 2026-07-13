package cmd

import (
	"testing"
)

func TestShouldStartEmbeddedRelay_NoAuthSecret(t *testing.T) {
	c := &CombinedConfig{}
	if c.shouldStartEmbeddedRelay(false) {
		t.Error("expected false when authSecret is empty")
	}
	if c.shouldStartEmbeddedRelay(true) {
		t.Error("expected false when authSecret is empty and external relay exists")
	}
}

func TestShouldStartEmbeddedRelay_AuthSecretNoExternalRelay(t *testing.T) {
	c := &CombinedConfig{}
	c.Server.AuthSecret = "secret"
	if !c.shouldStartEmbeddedRelay(false) {
		t.Error("expected true when authSecret is set and no external relay")
	}
}

func TestShouldStartEmbeddedRelay_AuthSecretMatchingExternal(t *testing.T) {
	c := &CombinedConfig{}
	c.Server.AuthSecret = "shared-secret"
	c.Server.Relays.Secret = "shared-secret"
	if !c.shouldStartEmbeddedRelay(true) {
		t.Error("expected true when authSecret matches relays.secret")
	}
}

func TestShouldStartEmbeddedRelay_AuthSecretMismatchExternal(t *testing.T) {
	c := &CombinedConfig{}
	c.Server.AuthSecret = "auth-secret"
	c.Server.Relays.Secret = "relay-secret"
	if c.shouldStartEmbeddedRelay(true) {
		t.Error("expected false when authSecret differs from relays.secret")
	}
}

func TestApplyRelayDefaults_EmbeddedRelayStartsWithoutExternal(t *testing.T) {
	c := &CombinedConfig{}
	c.Server.AuthSecret = "secret"
	c.applyRelayDefaults("https", "example.com:443", false)
	if !c.Relay.Enabled {
		t.Error("expected relay enabled when authSecret is set")
	}
	if c.Relay.ExposedAddress != "rels://example.com:443" {
		t.Errorf("expected relay address rels://example.com:443, got %s", c.Relay.ExposedAddress)
	}
	if c.Relay.AuthSecret != "secret" {
		t.Error("expected auth secret propagated to relay")
	}
}

func TestApplyRelayDefaults_ExternalRelaySecretMismatch(t *testing.T) {
	c := &CombinedConfig{}
	c.Server.AuthSecret = "auth-secret"
	c.Server.Relays.Secret = "different-secret"
	c.applyRelayDefaults("https", "example.com:443", true)
	if c.Relay.Enabled {
		t.Error("expected relay disabled when secrets mismatch")
	}
}

func TestApplyRelayDefaults_ExternalRelaySecretMatch(t *testing.T) {
	c := &CombinedConfig{}
	c.Server.AuthSecret = "shared-secret"
	c.Server.Relays.Secret = "shared-secret"
	c.applyRelayDefaults("https", "example.com:443", true)
	if !c.Relay.Enabled {
		t.Error("expected relay enabled when secrets match")
	}
	if c.Relay.ExposedAddress != "rels://example.com:443" {
		t.Errorf("expected relay address rels://example.com:443, got %s", c.Relay.ExposedAddress)
	}
	if c.Relay.AuthSecret != "shared-secret" {
		t.Error("expected auth secret propagated to relay")
	}
}

func TestApplyRelayDefaults_StunEnabledWhenStunPortsSet(t *testing.T) {
	c := &CombinedConfig{}
	c.Server.AuthSecret = "secret"
	c.Server.StunPorts = []int{3478}
	c.applyRelayDefaults("https", "example.com:443", false)
	if !c.Relay.Stun.Enabled {
		t.Error("expected STUN enabled when stunPorts is set")
	}
	if len(c.Relay.Stun.Ports) != 1 || c.Relay.Stun.Ports[0] != 3478 {
		t.Errorf("expected STUN ports [3478], got %v", c.Relay.Stun.Ports)
	}
}

func TestAutoConfigureClientSettings_RelayListExternalAndEmbedded(t *testing.T) {
	c := &CombinedConfig{}
	c.Server.AuthSecret = "shared-secret"
	c.Server.Relays = RelaysConfig{
		Addresses:      []string{"rels://external.example.com:443"},
		Secret:         "shared-secret",
		CredentialsTTL: "12h",
	}
	c.autoConfigureClientSettings("https", "local.example.com", "local.example.com:443", false, true, false)
	expectedEmbedded := "rels://local.example.com:443"
	if len(c.Management.Relays.Addresses) != 2 {
		t.Fatalf("expected 2 relay addresses, got %d: %v", len(c.Management.Relays.Addresses), c.Management.Relays.Addresses)
	}
	if c.Management.Relays.Addresses[0] != expectedEmbedded {
		t.Errorf("expected embedded relay first (preferred), got %s", c.Management.Relays.Addresses[0])
	}
	if c.Management.Relays.Addresses[1] != "rels://external.example.com:443" {
		t.Errorf("expected external relay second, got %s", c.Management.Relays.Addresses[1])
	}
}

func TestAutoConfigureClientSettings_RelayListExternalOnly(t *testing.T) {
	c := &CombinedConfig{}
	c.Server.AuthSecret = ""
	c.Server.Relays = RelaysConfig{
		Addresses:      []string{"rels://external.example.com:443"},
		CredentialsTTL: "12h",
	}
	c.autoConfigureClientSettings("https", "local.example.com", "local.example.com:443", false, true, false)
	if len(c.Management.Relays.Addresses) != 1 {
		t.Fatalf("expected 1 relay address, got %d: %v", len(c.Management.Relays.Addresses), c.Management.Relays.Addresses)
	}
	if c.Management.Relays.Addresses[0] != "rels://external.example.com:443" {
		t.Errorf("expected external relay only, got %s", c.Management.Relays.Addresses[0])
	}
}

func TestAutoConfigureClientSettings_RelayListEmbeddedOnly(t *testing.T) {
	c := &CombinedConfig{}
	c.Server.AuthSecret = "secret"
	c.autoConfigureClientSettings("https", "local.example.com", "local.example.com:443", false, false, false)
	if len(c.Management.Relays.Addresses) != 1 {
		t.Fatalf("expected 1 relay address, got %d: %v", len(c.Management.Relays.Addresses), c.Management.Relays.Addresses)
	}
	if c.Management.Relays.Addresses[0] != "rels://local.example.com:443" {
		t.Errorf("expected embedded relay, got %s", c.Management.Relays.Addresses[0])
	}
}

func TestAutoConfigureClientSettings_StunAdditiveWithExternal(t *testing.T) {
	c := &CombinedConfig{}
	c.Server.AuthSecret = "secret"
	c.Server.StunPorts = []int{3478, 3479}
	c.Server.Stuns = []HostConfig{
		{URI: "stun:external-stun.example.com:3478"},
	}
	c.autoConfigureClientSettings("https", "local.example.com", "local.example.com:443", true, false, false)
	if len(c.Management.Stuns) != 3 {
		t.Fatalf("expected 3 STUN addresses (1 external + 2 local), got %d: %v", len(c.Management.Stuns), c.Management.Stuns)
	}
	if c.Management.Stuns[0].URI != "stun:external-stun.example.com:3478" {
		t.Errorf("expected external STUN first, got %s", c.Management.Stuns[0].URI)
	}
	if c.Management.Stuns[1].URI != "stun:local.example.com:3478" {
		t.Errorf("expected local STUN on port 3478 at index 1, got %s", c.Management.Stuns[1].URI)
	}
	if c.Management.Stuns[2].URI != "stun:local.example.com:3479" {
		t.Errorf("expected local STUN on port 3479 at index 2, got %s", c.Management.Stuns[2].URI)
	}
}

func TestAutoConfigureClientSettings_StunExternalReplacesWhenEmbeddedDisabled(t *testing.T) {
	c := &CombinedConfig{}
	c.Server.AuthSecret = ""
	c.Server.StunPorts = []int{3478}
	c.Server.Stuns = []HostConfig{
		{URI: "stun:external-stun.example.com:3478"},
	}
	c.autoConfigureClientSettings("https", "local.example.com", "local.example.com:443", true, false, false)
	if len(c.Management.Stuns) != 1 {
		t.Fatalf("expected 1 STUN address (external only), got %d: %v", len(c.Management.Stuns), c.Management.Stuns)
	}
	if c.Management.Stuns[0].URI != "stun:external-stun.example.com:3478" {
		t.Errorf("expected external STUN only, got %s", c.Management.Stuns[0].URI)
	}
}

func TestAutoConfigureClientSettings_RelaySecretFallsBackToAuthSecret(t *testing.T) {
	c := &CombinedConfig{}
	c.Server.AuthSecret = "my-secret"
	c.Server.Relays.CredentialsTTL = "12h"
	c.autoConfigureClientSettings("http", "local.example.com", "local.example.com:80", false, false, false)
	if c.Management.Relays.Secret != "my-secret" {
		t.Errorf("expected relays secret to fallback to authSecret, got %s", c.Management.Relays.Secret)
	}
}