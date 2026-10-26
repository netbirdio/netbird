package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
)

const baseServerYAML = `
server:
  exposedAddress: "https://netbird.example.com:443"
  authSecret: "local-secret"
  dataDir: "/var/lib/netbird"
`

func loadTestConfig(t *testing.T, yaml string) *CombinedConfig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(yaml), 0o600))
	cfg, err := LoadConfig(path)
	require.NoError(t, err)
	return cfg
}

func stunURIs(hosts []HostConfig) []string {
	var uris []string
	for _, h := range hosts {
		uris = append(uris, h.URI)
	}
	return uris
}

type serviceExpectation struct {
	relayEnabled      bool
	stunEnabled       bool
	stunPorts         []int
	signalEnabled     bool
	clientStuns       []string
	clientRelays      []string
	clientRelaySecret string
	clientSignalURI   string
}

func assertServices(t *testing.T, cfg *CombinedConfig, want serviceExpectation) {
	t.Helper()
	assert.Equal(t, want.relayEnabled, cfg.Relay.Enabled, "local relay enabled")
	assert.Equal(t, want.stunEnabled, cfg.Relay.Stun.Enabled, "local STUN enabled")
	if want.stunEnabled {
		assert.Equal(t, want.stunPorts, cfg.Relay.Stun.Ports, "local STUN ports")
	}
	assert.Equal(t, want.signalEnabled, cfg.Signal.Enabled, "local signal enabled")
	assert.True(t, cfg.Management.Enabled, "management is always enabled")
	assert.Equal(t, want.clientStuns, stunURIs(cfg.Management.Stuns), "STUN servers sent to clients")
	assert.Equal(t, want.clientRelays, cfg.Management.Relays.Addresses, "relay addresses sent to clients")
	assert.Equal(t, want.clientRelaySecret, cfg.Management.Relays.Secret, "relay secret used to sign client tokens")
	assert.Equal(t, want.clientSignalURI, cfg.Management.SignalURI, "signal URI sent to clients")
}

func TestApplySimplifiedDefaultsServices(t *testing.T) {
	tests := []struct {
		name  string
		yaml  string
		want  serviceExpectation
		check func(t *testing.T, cfg *CombinedConfig)
	}{
		{
			name: "everything embedded by default",
			yaml: baseServerYAML,
			want: serviceExpectation{
				relayEnabled:      true,
				stunEnabled:       true,
				stunPorts:         []int{3478},
				signalEnabled:     true,
				clientStuns:       []string{"stun:netbird.example.com:3478"},
				clientRelays:      []string{"rels://netbird.example.com:443"},
				clientRelaySecret: "local-secret",
				clientSignalURI:   "https://netbird.example.com:443",
			},
			check: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, "rels://netbird.example.com:443", cfg.Relay.ExposedAddress, "local relay exposed address")
				assert.Equal(t, "local-secret", cfg.Relay.AuthSecret, "local relay validates with authSecret")
			},
		},
		{
			name: "plain http exposed address uses rel scheme",
			yaml: `
server:
  exposedAddress: "http://netbird.example.com:8080"
  authSecret: "local-secret"
  dataDir: "/var/lib/netbird"
`,
			want: serviceExpectation{
				relayEnabled:      true,
				stunEnabled:       true,
				stunPorts:         []int{3478},
				signalEnabled:     true,
				clientStuns:       []string{"stun:netbird.example.com:3478"},
				clientRelays:      []string{"rel://netbird.example.com:8080"},
				clientRelaySecret: "local-secret",
				clientSignalURI:   "http://netbird.example.com:8080",
			},
		},
		{
			name: "IPv6 exposed address",
			yaml: `
server:
  exposedAddress: "https://[2001:db8::1]:443"
  authSecret: "local-secret"
  dataDir: "/var/lib/netbird"
`,
			want: serviceExpectation{
				relayEnabled:      true,
				stunEnabled:       true,
				stunPorts:         []int{3478},
				signalEnabled:     true,
				clientStuns:       []string{"stun:[2001:db8::1]:3478"},
				clientRelays:      []string{"rels://[2001:db8::1]:443"},
				clientRelaySecret: "local-secret",
				clientSignalURI:   "https://[2001:db8::1]:443",
			},
		},
		{
			name: "custom STUN ports",
			yaml: baseServerYAML + `
  stunPorts: [3478, 3479]
`,
			want: serviceExpectation{
				relayEnabled:      true,
				stunEnabled:       true,
				stunPorts:         []int{3478, 3479},
				signalEnabled:     true,
				clientStuns:       []string{"stun:netbird.example.com:3478", "stun:netbird.example.com:3479"},
				clientRelays:      []string{"rels://netbird.example.com:443"},
				clientRelaySecret: "local-secret",
				clientSignalURI:   "https://netbird.example.com:443",
			},
		},
		{
			name: "empty STUN ports fall back to 3478",
			yaml: baseServerYAML + `
  stunPorts: []
`,
			want: serviceExpectation{
				relayEnabled:      true,
				stunEnabled:       true,
				stunPorts:         []int{3478},
				signalEnabled:     true,
				clientStuns:       []string{"stun:netbird.example.com:3478"},
				clientRelays:      []string{"rels://netbird.example.com:443"},
				clientRelaySecret: "local-secret",
				clientSignalURI:   "https://netbird.example.com:443",
			},
		},
		{
			name: "external STUN replaces local STUN",
			yaml: baseServerYAML + `
  stuns:
    - uri: "stun:stun.example.com:3478"
`,
			want: serviceExpectation{
				relayEnabled:      true,
				stunEnabled:       false,
				signalEnabled:     true,
				clientStuns:       []string{"stun:stun.example.com:3478"},
				clientRelays:      []string{"rels://netbird.example.com:443"},
				clientRelaySecret: "local-secret",
				clientSignalURI:   "https://netbird.example.com:443",
			},
		},
		{
			// Documented behavior: an external relay also turns off the embedded
			// STUN server, yet the local STUN address is still sent to clients.
			// This works only when the external relay serves STUN on the same host.
			name: "external relay without external STUN",
			yaml: baseServerYAML + `
  relays:
    addresses: ["rels://relay.example.com:443"]
    secret: "external-secret"
    credentialsTTL: "24h"
`,
			want: serviceExpectation{
				relayEnabled:      false,
				stunEnabled:       false,
				signalEnabled:     true,
				clientStuns:       []string{"stun:netbird.example.com:3478"},
				clientRelays:      []string{"rels://relay.example.com:443"},
				clientRelaySecret: "external-secret",
				clientSignalURI:   "https://netbird.example.com:443",
			},
			check: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, "24h", cfg.Management.Relays.CredentialsTTL, "external credentials TTL is kept")
			},
		},
		{
			name: "external relay without secret signs with authSecret",
			yaml: baseServerYAML + `
  relays:
    addresses: ["rels://relay.example.com:443"]
  stuns:
    - uri: "stun:relay.example.com:3478"
`,
			want: serviceExpectation{
				relayEnabled:      false,
				stunEnabled:       false,
				signalEnabled:     true,
				clientStuns:       []string{"stun:relay.example.com:3478"},
				clientRelays:      []string{"rels://relay.example.com:443"},
				clientRelaySecret: "local-secret",
				clientSignalURI:   "https://netbird.example.com:443",
			},
			check: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, "12h", cfg.Management.Relays.CredentialsTTL, "default credentials TTL")
			},
		},
		{
			name: "external signal",
			yaml: baseServerYAML + `
  signalUri: "https://signal.example.com:443"
`,
			want: serviceExpectation{
				relayEnabled:      true,
				stunEnabled:       true,
				stunPorts:         []int{3478},
				signalEnabled:     false,
				clientStuns:       []string{"stun:netbird.example.com:3478"},
				clientRelays:      []string{"rels://netbird.example.com:443"},
				clientRelaySecret: "local-secret",
				clientSignalURI:   "https://signal.example.com:443",
			},
		},
		{
			name: "disableStun runs and advertises no STUN",
			yaml: baseServerYAML + `
  disableStun: true
`,
			want: serviceExpectation{
				relayEnabled:      true,
				stunEnabled:       false,
				signalEnabled:     true,
				clientRelays:      []string{"rels://netbird.example.com:443"},
				clientRelaySecret: "local-secret",
				clientSignalURI:   "https://netbird.example.com:443",
			},
		},
		{
			name: "disableStun ignores stunPorts",
			yaml: baseServerYAML + `
  disableStun: true
  stunPorts: [3478, 3479]
`,
			want: serviceExpectation{
				relayEnabled:      true,
				stunEnabled:       false,
				signalEnabled:     true,
				clientRelays:      []string{"rels://netbird.example.com:443"},
				clientRelaySecret: "local-secret",
				clientSignalURI:   "https://netbird.example.com:443",
			},
		},
		{
			name: "disableRelay keeps local STUN running",
			yaml: `
server:
  exposedAddress: "https://netbird.example.com:443"
  dataDir: "/var/lib/netbird"
  disableRelay: true
`,
			want: serviceExpectation{
				relayEnabled:    false,
				stunEnabled:     true,
				stunPorts:       []int{3478},
				signalEnabled:   true,
				clientStuns:     []string{"stun:netbird.example.com:3478"},
				clientSignalURI: "https://netbird.example.com:443",
			},
		},
		{
			name: "disableRelay with external STUN",
			yaml: baseServerYAML + `
  disableRelay: true
  stuns:
    - uri: "stun:stun.example.com:3478"
`,
			want: serviceExpectation{
				relayEnabled:    false,
				stunEnabled:     false,
				signalEnabled:   true,
				clientStuns:     []string{"stun:stun.example.com:3478"},
				clientSignalURI: "https://netbird.example.com:443",
			},
		},
		{
			name: "disableRelay and disableStun",
			yaml: baseServerYAML + `
  disableRelay: true
  disableStun: true
`,
			want: serviceExpectation{
				relayEnabled:    false,
				stunEnabled:     false,
				signalEnabled:   true,
				clientSignalURI: "https://netbird.example.com:443",
			},
		},
		{
			name: "keepEmbeddedStun advertises external then local STUN",
			yaml: baseServerYAML + `
  keepEmbeddedStun: true
  stuns:
    - uri: "stun:stun.example.com:3478"
`,
			want: serviceExpectation{
				relayEnabled:      true,
				stunEnabled:       true,
				stunPorts:         []int{3478},
				signalEnabled:     true,
				clientStuns:       []string{"stun:stun.example.com:3478", "stun:netbird.example.com:3478"},
				clientRelays:      []string{"rels://netbird.example.com:443"},
				clientRelaySecret: "local-secret",
				clientSignalURI:   "https://netbird.example.com:443",
			},
		},
		{
			name: "keepEmbeddedStun with custom ports",
			yaml: baseServerYAML + `
  keepEmbeddedStun: true
  stunPorts: [3479]
  stuns:
    - uri: "stun:stun.example.com:3478"
`,
			want: serviceExpectation{
				relayEnabled:      true,
				stunEnabled:       true,
				stunPorts:         []int{3479},
				signalEnabled:     true,
				clientStuns:       []string{"stun:stun.example.com:3478", "stun:netbird.example.com:3479"},
				clientRelays:      []string{"rels://netbird.example.com:443"},
				clientRelaySecret: "local-secret",
				clientSignalURI:   "https://netbird.example.com:443",
			},
		},
		{
			name: "keepEmbeddedRelay advertises external and local relays",
			yaml: baseServerYAML + `
  keepEmbeddedRelay: true
  relays:
    addresses: ["rels://relay.example.com:443"]
  stuns:
    - uri: "stun:relay.example.com:3478"
`,
			want: serviceExpectation{
				relayEnabled:      true,
				stunEnabled:       false,
				signalEnabled:     true,
				clientStuns:       []string{"stun:relay.example.com:3478"},
				clientRelays:      []string{"rels://relay.example.com:443", "rels://netbird.example.com:443"},
				clientRelaySecret: "local-secret",
				clientSignalURI:   "https://netbird.example.com:443",
			},
			check: func(t *testing.T, cfg *CombinedConfig) {
				assert.Equal(t, []string{"rels://relay.example.com:443"}, cfg.Server.Relays.Addresses, "server relays are not modified")
			},
		},
		{
			// Without external STUN the local STUN follows the local relay, as it
			// did before STUN was split from the relay.
			name: "keepEmbeddedRelay without external STUN runs local STUN",
			yaml: baseServerYAML + `
  keepEmbeddedRelay: true
  relays:
    addresses: ["rels://relay.example.com:443"]
    secret: "local-secret"
`,
			want: serviceExpectation{
				relayEnabled:      true,
				stunEnabled:       true,
				stunPorts:         []int{3478},
				signalEnabled:     true,
				clientStuns:       []string{"stun:netbird.example.com:3478"},
				clientRelays:      []string{"rels://relay.example.com:443", "rels://netbird.example.com:443"},
				clientRelaySecret: "local-secret",
				clientSignalURI:   "https://netbird.example.com:443",
			},
		},
		{
			name: "keep flags without external servers change nothing",
			yaml: baseServerYAML + `
  keepEmbeddedStun: true
  keepEmbeddedRelay: true
`,
			want: serviceExpectation{
				relayEnabled:      true,
				stunEnabled:       true,
				stunPorts:         []int{3478},
				signalEnabled:     true,
				clientStuns:       []string{"stun:netbird.example.com:3478"},
				clientRelays:      []string{"rels://netbird.example.com:443"},
				clientRelaySecret: "local-secret",
				clientSignalURI:   "https://netbird.example.com:443",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := loadTestConfig(t, tt.yaml)
			require.NoError(t, cfg.Validate())
			assertServices(t, cfg, tt.want)
			if tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}

func TestValidateServices(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "local relay requires authSecret",
			yaml: `
server:
  exposedAddress: "https://netbird.example.com:443"
  dataDir: "/var/lib/netbird"
`,
			wantErr: "server.authSecret is required",
		},
		{
			name: "external relay does not require authSecret",
			yaml: `
server:
  exposedAddress: "https://netbird.example.com:443"
  dataDir: "/var/lib/netbird"
  relays:
    addresses: ["rels://relay.example.com:443"]
    secret: "external-secret"
`,
		},
		{
			name: "disableRelay does not require authSecret",
			yaml: `
server:
  exposedAddress: "https://netbird.example.com:443"
  dataDir: "/var/lib/netbird"
  disableRelay: true
`,
		},
		{
			name: "keepEmbeddedRelay requires authSecret",
			yaml: `
server:
  exposedAddress: "https://netbird.example.com:443"
  dataDir: "/var/lib/netbird"
  keepEmbeddedRelay: true
  relays:
    addresses: ["rels://relay.example.com:443"]
`,
			wantErr: "server.authSecret is required",
		},
		{
			name: "keepEmbeddedRelay rejects a different relay secret",
			yaml: baseServerYAML + `
  keepEmbeddedRelay: true
  relays:
    addresses: ["rels://relay.example.com:443"]
    secret: "external-secret"
`,
			wantErr: "server.relays.secret must match server.authSecret",
		},
		{
			name: "keepEmbeddedRelay accepts the same relay secret",
			yaml: baseServerYAML + `
  keepEmbeddedRelay: true
  relays:
    addresses: ["rels://relay.example.com:443"]
    secret: "local-secret"
`,
		},
		{
			name: "disableStun with external STUN",
			yaml: baseServerYAML + `
  disableStun: true
  stuns:
    - uri: "stun:stun.example.com:3478"
`,
			wantErr: "server.disableStun and server.stuns are mutually exclusive",
		},
		{
			name: "disableStun with keepEmbeddedStun",
			yaml: baseServerYAML + `
  disableStun: true
  keepEmbeddedStun: true
`,
			wantErr: "server.disableStun and server.keepEmbeddedStun are mutually exclusive",
		},
		{
			name: "disableRelay with external relay",
			yaml: baseServerYAML + `
  disableRelay: true
  relays:
    addresses: ["rels://relay.example.com:443"]
`,
			wantErr: "server.disableRelay and server.relays.addresses are mutually exclusive",
		},
		{
			name: "disableRelay with keepEmbeddedRelay",
			yaml: baseServerYAML + `
  disableRelay: true
  keepEmbeddedRelay: true
`,
			wantErr: "server.disableRelay and server.keepEmbeddedRelay are mutually exclusive",
		},
		{
			name: "STUN port out of range",
			yaml: baseServerYAML + `
  stunPorts: [70000]
`,
			wantErr: "invalid server.stunPorts value 70000",
		},
		{
			name: "duplicate STUN port",
			yaml: baseServerYAML + `
  stunPorts: [3478, 3478]
`,
			wantErr: "duplicate STUN port 3478",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := loadTestConfig(t, tt.yaml).Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr, "validation error message")
		})
	}
}

func TestToManagementConfigServices(t *testing.T) {
	t.Run("embedded services", func(t *testing.T) {
		mgmtCfg, err := loadTestConfig(t, baseServerYAML).ToManagementConfig()
		require.NoError(t, err)

		require.Len(t, mgmtCfg.Stuns, 1, "one STUN host")
		assert.Equal(t, "stun:netbird.example.com:3478", mgmtCfg.Stuns[0].URI, "STUN URI")
		assert.Equal(t, nbconfig.UDP, mgmtCfg.Stuns[0].Proto, "STUN protocol")

		require.NotNil(t, mgmtCfg.Relay, "relay config")
		assert.Equal(t, []string{"rels://netbird.example.com:443"}, mgmtCfg.Relay.Addresses, "relay addresses")
		assert.Equal(t, "local-secret", mgmtCfg.Relay.Secret, "relay secret")
		assert.Equal(t, 12*time.Hour, mgmtCfg.Relay.CredentialsTTL.Duration, "relay credentials TTL")

		require.NotNil(t, mgmtCfg.Signal, "signal config")
		assert.Equal(t, "netbird.example.com:443", mgmtCfg.Signal.URI, "signal URI")
		assert.Equal(t, nbconfig.HTTPS, mgmtCfg.Signal.Proto, "signal protocol")
	})

	t.Run("external relay keeps its addresses and secret", func(t *testing.T) {
		cfg := loadTestConfig(t, baseServerYAML+`
  relays:
    addresses: ["rels://relay-a.example.com:443", "rels://relay-b.example.com:443"]
    secret: "external-secret"
  stuns:
    - uri: "stun:relay-a.example.com:3478"
`)
		mgmtCfg, err := cfg.ToManagementConfig()
		require.NoError(t, err)

		require.NotNil(t, mgmtCfg.Relay, "relay config")
		assert.Equal(t, []string{"rels://relay-a.example.com:443", "rels://relay-b.example.com:443"}, mgmtCfg.Relay.Addresses, "relay addresses")
		assert.Equal(t, "external-secret", mgmtCfg.Relay.Secret, "relay secret")
		require.Len(t, mgmtCfg.Stuns, 1, "one STUN host")
		assert.Equal(t, "stun:relay-a.example.com:3478", mgmtCfg.Stuns[0].URI, "STUN URI")
	})

	t.Run("disabled relay and STUN send nothing to clients", func(t *testing.T) {
		cfg := loadTestConfig(t, baseServerYAML+`
  disableRelay: true
  disableStun: true
`)
		mgmtCfg, err := cfg.ToManagementConfig()
		require.NoError(t, err)

		assert.Nil(t, mgmtCfg.Relay, "no relay config")
		assert.Empty(t, mgmtCfg.Stuns, "no STUN hosts")
		assert.NotNil(t, mgmtCfg.Signal, "signal is unaffected")
	})
}
