package grpc

import (
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller/cache"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// TestToPeerConfig_ConnectionModeResolution covers Phase 1 of issue #5989:
// the management server resolves the effective ConnectionMode from
// Settings (with the new ConnectionMode field winning over the legacy
// LazyConnectionEnabled boolean), then writes BOTH wire fields so old
// clients (boolean only) and new clients (enum only) see consistent
// behaviour.
func TestToPeerConfig_ConnectionModeResolution(t *testing.T) {
	cases := []struct {
		name             string
		settingsMode     *string
		settingsLazyBool bool
		settingsRelayTO  *uint32
		settingsP2pTO    *uint32
		wantPCMode       mgmProto.ConnectionMode
		wantPCLazyBool   bool
		wantPCRelayTO    uint32
		wantPCP2pTO      uint32
	}{
		{
			name:           "no settings -> P2P + lazy=false",
			wantPCMode:     mgmProto.ConnectionMode_CONNECTION_MODE_P2P,
			wantPCLazyBool: false,
		},
		{
			name:             "only legacy lazy=true -> P2P_LAZY + lazy=true",
			settingsLazyBool: true,
			wantPCMode:       mgmProto.ConnectionMode_CONNECTION_MODE_P2P_LAZY,
			wantPCLazyBool:   true,
		},
		{
			name:           "ConnectionMode=p2p-lazy explicit -> P2P_LAZY + lazy=true",
			settingsMode:   strPtrTest("p2p-lazy"),
			wantPCMode:     mgmProto.ConnectionMode_CONNECTION_MODE_P2P_LAZY,
			wantPCLazyBool: true,
		},
		{
			name:           "ConnectionMode=p2p explicit -> P2P + lazy=false",
			settingsMode:   strPtrTest("p2p"),
			wantPCMode:     mgmProto.ConnectionMode_CONNECTION_MODE_P2P,
			wantPCLazyBool: false,
		},
		{
			name:           "ConnectionMode=relay-forced -> RELAY_FORCED + lazy=false (structural compat gap)",
			settingsMode:   strPtrTest("relay-forced"),
			wantPCMode:     mgmProto.ConnectionMode_CONNECTION_MODE_RELAY_FORCED,
			wantPCLazyBool: false,
		},
		{
			name:             "ConnectionMode wins over conflicting legacy bool",
			settingsMode:     strPtrTest("relay-forced"),
			settingsLazyBool: true, // ignored
			wantPCMode:       mgmProto.ConnectionMode_CONNECTION_MODE_RELAY_FORCED,
			wantPCLazyBool:   false,
		},
		{
			name:            "RelayTimeout propagates",
			settingsMode:    strPtrTest("p2p-lazy"),
			settingsRelayTO: u32PtrTest(42),
			wantPCMode:      mgmProto.ConnectionMode_CONNECTION_MODE_P2P_LAZY,
			wantPCLazyBool:  true,
			wantPCRelayTO:   42,
		},
		{
			name:           "P2pTimeout propagates",
			settingsMode:   strPtrTest("p2p-dynamic"),
			settingsP2pTO:  u32PtrTest(180),
			wantPCMode:     mgmProto.ConnectionMode_CONNECTION_MODE_P2P_DYNAMIC,
			wantPCLazyBool: false, // p2p-dynamic maps to lazy=false (best-match for old clients)
			wantPCP2pTO:    180,
		},
		{
			name:           "Garbage in ConnectionMode falls back to legacy bool",
			settingsMode:   strPtrTest("not-a-mode"),
			settingsLazyBool: true,
			wantPCMode:     mgmProto.ConnectionMode_CONNECTION_MODE_P2P_LAZY,
			wantPCLazyBool: true,
		},
	}

	// Minimal Network and Peer fixtures shared across cases.
	_, ipnet, _ := net.ParseCIDR("10.0.0.0/16")
	network := &types.Network{Net: *ipnet}
	peer := &nbpeer.Peer{
		ID:       "p1",
		Name:     "test-peer",
		DNSLabel: "test-peer",
		IP:       net.IPv4(10, 0, 0, 5),
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			settings := &types.Settings{
				LazyConnectionEnabled: c.settingsLazyBool,
				ConnectionMode:        c.settingsMode,
				RelayTimeoutSeconds:   c.settingsRelayTO,
				P2pTimeoutSeconds:     c.settingsP2pTO,
			}
			pc := toPeerConfig(peer, network, "example.local", settings, nil, nil, false)

			assert.Equal(t, c.wantPCMode, pc.GetConnectionMode(),
				"ConnectionMode wire field")
			assert.Equal(t, c.wantPCLazyBool, pc.GetLazyConnectionEnabled(),
				"LazyConnectionEnabled wire field (backwards-compat)")
			assert.Equal(t, c.wantPCRelayTO, pc.GetRelayTimeoutSeconds(),
				"RelayTimeoutSeconds wire field")
			assert.Equal(t, c.wantPCP2pTO, pc.GetP2PTimeoutSeconds(),
				"P2PTimeoutSeconds wire field")
		})
	}
}

func strPtrTest(s string) *string  { return &s }
func u32PtrTest(v uint32) *uint32  { return &v }

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

			result := buildJWTConfig(config, nil)

			assert.NotNil(t, result)
			assert.Equal(t, tc.expectedAudiences, result.Audiences, "audiences should match expected")
			//nolint:staticcheck // SA1019: Testing backwards compatibility - Audience field must still be populated
			assert.Equal(t, tc.expectedAudience, result.Audience, "audience should match expected")
		})
	}
}
