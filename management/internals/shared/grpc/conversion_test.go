package grpc

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller/cache"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/types"
)

func TestToProtocolDNSConfigWithCache(t *testing.T) {
	var cache cache.DNSConfigCache

	// Create two different configs
	config1 := nbdns.Config{
		ServiceEnable: true,
		CustomZones: []nbdns.CustomZone{
			{
				Domain: "example.com",
				Records: []nbdns.SimpleRecord{
					{Name: "www", Type: 1, Class: "IN", TTL: 300, RData: "192.168.1.1"},
				},
			},
		},
		NameServerGroups: []*nbdns.NameServerGroup{
			{
				ID:   "group1",
				Name: "Group 1",
				NameServers: []nbdns.NameServer{
					{IP: netip.MustParseAddr("8.8.8.8"), Port: 53},
				},
			},
		},
	}

	config2 := nbdns.Config{
		ServiceEnable: true,
		CustomZones: []nbdns.CustomZone{
			{
				Domain: "example.org",
				Records: []nbdns.SimpleRecord{
					{Name: "mail", Type: 1, Class: "IN", TTL: 300, RData: "192.168.1.2"},
				},
			},
		},
		NameServerGroups: []*nbdns.NameServerGroup{
			{
				ID:   "group2",
				Name: "Group 2",
				NameServers: []nbdns.NameServer{
					{IP: netip.MustParseAddr("8.8.4.4"), Port: 53},
				},
			},
		},
	}

	// First run with config1
	result1 := toProtocolDNSConfig(config1, &cache, int64(network_map.DnsForwarderPort))

	// Second run with config2
	result2 := toProtocolDNSConfig(config2, &cache, int64(network_map.DnsForwarderPort))

	// Third run with config1 again
	result3 := toProtocolDNSConfig(config1, &cache, int64(network_map.DnsForwarderPort))

	// Verify that result1 and result3 are identical
	if !reflect.DeepEqual(result1, result3) {
		t.Errorf("Results are not identical when run with the same input. Expected %v, got %v", result1, result3)
	}

	// Verify that result2 is different from result1 and result3
	if reflect.DeepEqual(result1, result2) || reflect.DeepEqual(result2, result3) {
		t.Errorf("Results should be different for different inputs")
	}

	if _, exists := cache.GetNameServerGroup("group1"); !exists {
		t.Errorf("Cache should contain name server group 'group1'")
	}

	if _, exists := cache.GetNameServerGroup("group2"); !exists {
		t.Errorf("Cache should contain name server group 'group2'")
	}
}

func BenchmarkToProtocolDNSConfig(b *testing.B) {
	sizes := []int{10, 100, 1000}

	for _, size := range sizes {
		testData := generateTestData(size)

		b.Run(fmt.Sprintf("WithCache-Size%d", size), func(b *testing.B) {
			cache := &cache.DNSConfigCache{}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				toProtocolDNSConfig(testData, cache, int64(network_map.DnsForwarderPort))
			}
		})

		b.Run(fmt.Sprintf("WithoutCache-Size%d", size), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				cache := &cache.DNSConfigCache{}
				toProtocolDNSConfig(testData, cache, int64(network_map.DnsForwarderPort))
			}
		})
	}
}

func generateTestData(size int) nbdns.Config {
	config := nbdns.Config{
		ServiceEnable:    true,
		CustomZones:      make([]nbdns.CustomZone, size),
		NameServerGroups: make([]*nbdns.NameServerGroup, size),
	}

	for i := 0; i < size; i++ {
		config.CustomZones[i] = nbdns.CustomZone{
			Domain: fmt.Sprintf("domain%d.com", i),
			Records: []nbdns.SimpleRecord{
				{
					Name:  fmt.Sprintf("record%d", i),
					Type:  1,
					Class: "IN",
					TTL:   3600,
					RData: "192.168.1.1",
				},
			},
		}

		config.NameServerGroups[i] = &nbdns.NameServerGroup{
			ID:                   fmt.Sprintf("group%d", i),
			Primary:              i == 0,
			Domains:              []string{fmt.Sprintf("domain%d.com", i)},
			SearchDomainsEnabled: true,
			NameServers: []nbdns.NameServer{
				{
					IP:     netip.MustParseAddr("8.8.8.8"),
					Port:   53,
					NSType: 1,
				},
			},
		}
	}

	return config
}

func TestBuildJWTConfig_Audiences(t *testing.T) {
	tests := []struct {
		name              string
		authAudience      string
		cliAuthAudience   string
		expectedAudiences []string
		expectedAudience  string
	}{
		{
			name:              "only_auth_audience",
			authAudience:      "dashboard-aud",
			cliAuthAudience:   "",
			expectedAudiences: []string{"dashboard-aud"},
			expectedAudience:  "dashboard-aud",
		},
		{
			name:              "both_audiences_different",
			authAudience:      "dashboard-aud",
			cliAuthAudience:   "cli-aud",
			expectedAudiences: []string{"dashboard-aud", "cli-aud"},
			expectedAudience:  "cli-aud",
		},
		{
			name:              "both_audiences_same",
			authAudience:      "same-aud",
			cliAuthAudience:   "same-aud",
			expectedAudiences: []string{"same-aud"},
			expectedAudience:  "same-aud",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := &nbconfig.HttpServerConfig{
				AuthIssuer:      "https://issuer.example.com",
				AuthAudience:    tc.authAudience,
				CLIAuthAudience: tc.cliAuthAudience,
			}

			result := buildJWTConfig(config, nil, nil)

			assert.NotNil(t, result)
			assert.Equal(t, tc.expectedAudiences, result.Audiences, "audiences should match expected")
			//nolint:staticcheck // SA1019: Testing backwards compatibility - Audience field must still be populated
			assert.Equal(t, tc.expectedAudience, result.Audience, "audience should match expected")
		})
	}
}

// TestShouldSkipSendingDeprecatedRemotePeers covers the version gate that
// stops populating the deprecated top-level SyncResponse.RemotePeers field for
// peers new enough to read RemotePeers off the NetworkMap. Development builds
// are treated as latest and skip the field. The gate otherwise fails safe: a
// release version older than the boundary, or one that can't be parsed (empty,
// garbage, prereleases of the boundary) still receives the deprecated field so
// older/unknown clients keep working.
func TestShouldSkipSendingDeprecatedRemotePeers(t *testing.T) {
	tests := []struct {
		name        string
		peerVersion string
		wantSkip    bool
	}{
		{"exact boundary skips", "0.29.3", true},
		{"newer patch skips", "0.29.4", true},
		{"newer minor skips", "0.30.0", true},
		{"newer major skips", "1.0.0", true},
		{"v-prefixed newer skips", "v0.30.0", true},
		{"development build skips", "development", true},
		{"development build with commit skips", "development-abc123def456-dirty", true},
		{"older patch keeps field", "0.29.2", false},
		{"older minor keeps field", "0.28.0", false},
		{"prerelease of boundary keeps field", "0.29.3-SNAPSHOT", false},
		{"tagged dev prerelease keeps field", "v0.31.1-dev", false},
		{"empty version keeps field", "", false},
		{"garbage version keeps field", "not-a-version", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldSkipSendingDeprecatedRemotePeers(tc.peerVersion)
			assert.Equal(t, tc.wantSkip, got, "skip decision for peer version %q", tc.peerVersion)
		})
	}
}

// TestEncodeSessionExpiresAt pins the wire encoding the client's
// applySessionDeadline depends on:
//
//   - zero deadline  → &Timestamp{} (seconds=0, nanos=0): the explicit
//     "expiry disabled or peer is not SSO-tracked" sentinel.
//   - non-zero       → timestamppb.New(deadline): the absolute UTC deadline.
//
// The third state (nil pointer = "no info in this snapshot") is the caller's
// responsibility on the Sync path when settings could not be resolved; the
// helper itself never returns nil.
func TestEncodeSessionExpiresAt(t *testing.T) {
	t.Run("zero deadline encodes as explicit-zero sentinel", func(t *testing.T) {
		got := encodeSessionExpiresAt(time.Time{})
		assert.NotNil(t, got, "must not return nil; nil means 'no info', not 'disabled'")
		assert.Equal(t, int64(0), got.GetSeconds())
		assert.Equal(t, int32(0), got.GetNanos())
	})

	t.Run("non-zero deadline round-trips", func(t *testing.T) {
		deadline := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
		got := encodeSessionExpiresAt(deadline)
		assert.NotNil(t, got)
		assert.True(t, got.AsTime().Equal(deadline))
	})
}

// TestToNetbirdConfig_RelayInvariant guards against the v0.74.0 relay-wipe regression.
// Clients treat any non-nil NetbirdConfig as authoritative and interpret a missing relay
// section as relay disabled, wiping their relay URLs. toNetbirdConfig must therefore
// return nil when no server config is set (the fan-out network-map path) instead of a
// partial config, and a result built from a relay-enabled config must carry the relay
// section.
func TestToNetbirdConfig_RelayInvariant(t *testing.T) {
	settings := &types.Settings{MetricsPushEnabled: true}

	t.Run("nil server config returns nil config", func(t *testing.T) {
		nbCfg := toNetbirdConfig(nil, nil, nil, nil, settings)
		assert.Nil(t, nbCfg, "fan-out updates must not carry a partial NetbirdConfig even when settings are present")
	})

	t.Run("relay-enabled config carries relay section", func(t *testing.T) {
		cfg := &nbconfig.Config{
			Stuns: []*nbconfig.Host{{Proto: nbconfig.UDP, URI: "stun:stun.example.com:3478"}},
			TURNConfig: &nbconfig.TURNConfig{
				Turns: []*nbconfig.Host{{Proto: nbconfig.UDP, URI: "turn:turn.example.com:3478", Username: "user", Password: "pass"}},
			},
			Relay:  &nbconfig.Relay{Addresses: []string{"rels://relay.example.com:443"}},
			Signal: &nbconfig.Host{Proto: nbconfig.HTTP, URI: "signal.example.com:10000"},
		}
		relayToken := &Token{Payload: "token-payload", Signature: "token-signature"}

		nbCfg := toNetbirdConfig(cfg, nil, relayToken, nil, settings)
		require.NotNil(t, nbCfg)
		require.NotNil(t, nbCfg.Relay, "non-nil NetbirdConfig must include the relay section")
		assert.Equal(t, cfg.Relay.Addresses, nbCfg.Relay.Urls, "relay URLs should match the server config")
		assert.Equal(t, relayToken.Payload, nbCfg.Relay.TokenPayload, "relay token payload should be set")
		assert.Equal(t, relayToken.Signature, nbCfg.Relay.TokenSignature, "relay token signature should be set")
		require.NotNil(t, nbCfg.Metrics)
		assert.True(t, nbCfg.Metrics.Enabled, "metrics flag should carry the settings value")
	})
}
