package debug

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/anonymize"
	mgmProto "github.com/netbirdio/netbird/management/proto"
)

func TestAnonymizeStateFile(t *testing.T) {
	testState := map[string]json.RawMessage{
		"null_state": json.RawMessage("null"),
		"test_state": mustMarshal(map[string]any{
			// Test simple fields
			"public_ip":      "203.0.113.1",
			"private_ip":     "192.168.1.1",
			"protected_ip":   "100.64.0.1",
			"well_known_ip":  "8.8.8.8",
			"ipv6_addr":      "2001:db8::1",
			"private_ipv6":   "fd00::1",
			"domain":         "test.example.com",
			"uri":            "stun:stun.example.com:3478",
			"uri_with_ip":    "turn:203.0.113.1:3478",
			"netbird_domain": "device.netbird.cloud",

			// Test CIDR ranges
			"public_cidr":       "203.0.113.0/24",
			"private_cidr":      "192.168.0.0/16",
			"protected_cidr":    "100.64.0.0/10",
			"ipv6_cidr":         "2001:db8::/32",
			"private_ipv6_cidr": "fd00::/8",

			// Test nested structures
			"nested": map[string]any{
				"ip":     "203.0.113.2",
				"domain": "nested.example.com",
				"more_nest": map[string]any{
					"ip":     "203.0.113.3",
					"domain": "deep.example.com",
				},
			},

			// Test arrays
			"string_array": []any{
				"203.0.113.4",
				"test1.example.com",
				"test2.example.com",
			},
			"object_array": []any{
				map[string]any{
					"ip":     "203.0.113.5",
					"domain": "array1.example.com",
				},
				map[string]any{
					"ip":     "203.0.113.6",
					"domain": "array2.example.com",
				},
			},

			// Test multiple occurrences of same value
			"duplicate_ip":     "203.0.113.1",      // Same as public_ip
			"duplicate_domain": "test.example.com", // Same as domain

			// Test URIs with various schemes
			"stun_uri":  "stun:stun.example.com:3478",
			"turns_uri": "turns:turns.example.com:5349",
			"http_uri":  "http://web.example.com:80",
			"https_uri": "https://secure.example.com:443",

			// Test strings that might look like IPs but aren't
			"not_ip":         "300.300.300.300",
			"partial_ip":     "192.168",
			"ip_like_string": "1234.5678",

			// Test mixed content strings
			"mixed_content": "Server at 203.0.113.1 (test.example.com) on port 80",

			// Test empty and special values
			"empty_string":  "",
			"null_value":    nil,
			"numeric_value": 42,
			"boolean_value": true,
		}),
		"route_state": mustMarshal(map[string]any{
			"routes": []any{
				map[string]any{
					"network": "203.0.113.0/24",
					"gateway": "203.0.113.1",
					"domains": []any{
						"route1.example.com",
						"route2.example.com",
					},
				},
				map[string]any{
					"network": "2001:db8::/32",
					"gateway": "2001:db8::1",
					"domains": []any{
						"route3.example.com",
						"route4.example.com",
					},
				},
			},
			// Test map with IP/CIDR keys
			"refCountMap": map[string]any{
				"203.0.113.1/32": map[string]any{
					"Count": 1,
					"Out": map[string]any{
						"IP": "192.168.0.1",
						"Intf": map[string]any{
							"Name":  "eth0",
							"Index": 1,
						},
					},
				},
				"2001:db8::1/128": map[string]any{
					"Count": 1,
					"Out": map[string]any{
						"IP": "fe80::1",
						"Intf": map[string]any{
							"Name":  "eth0",
							"Index": 1,
						},
					},
				},
				"10.0.0.1/32": map[string]any{ // private IP should remain unchanged
					"Count": 1,
					"Out": map[string]any{
						"IP": "192.168.0.1",
					},
				},
			},
		}),
	}

	anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())

	// Pre-seed the domains we need to verify in the test assertions
	anonymizer.AnonymizeDomain("test.example.com")
	anonymizer.AnonymizeDomain("nested.example.com")
	anonymizer.AnonymizeDomain("deep.example.com")
	anonymizer.AnonymizeDomain("array1.example.com")

	err := anonymizeStateFile(&testState, anonymizer)
	require.NoError(t, err)

	// Helper function to unmarshal and get nested values
	var state map[string]any
	err = json.Unmarshal(testState["test_state"], &state)
	require.NoError(t, err)

	// Test null state remains unchanged
	require.Equal(t, "null", string(testState["null_state"]))

	// Basic assertions
	assert.NotEqual(t, "203.0.113.1", state["public_ip"])
	assert.Equal(t, "192.168.1.1", state["private_ip"])  // Private IP unchanged
	assert.Equal(t, "100.64.0.1", state["protected_ip"]) // Protected IP unchanged
	assert.Equal(t, "8.8.8.8", state["well_known_ip"])   // Well-known IP unchanged
	assert.NotEqual(t, "2001:db8::1", state["ipv6_addr"])
	assert.Equal(t, "fd00::1", state["private_ipv6"]) // Private IPv6 unchanged
	assert.NotEqual(t, "test.example.com", state["domain"])
	assert.True(t, strings.HasSuffix(state["domain"].(string), ".domain"))
	assert.Equal(t, "device.netbird.cloud", state["netbird_domain"]) // Netbird domain unchanged

	// CIDR ranges
	assert.NotEqual(t, "203.0.113.0/24", state["public_cidr"])
	assert.Contains(t, state["public_cidr"], "/24")           // Prefix preserved
	assert.Equal(t, "192.168.0.0/16", state["private_cidr"])  // Private CIDR unchanged
	assert.Equal(t, "100.64.0.0/10", state["protected_cidr"]) // Protected CIDR unchanged
	assert.NotEqual(t, "2001:db8::/32", state["ipv6_cidr"])
	assert.Contains(t, state["ipv6_cidr"], "/32") // IPv6 prefix preserved

	// Nested structures
	nested := state["nested"].(map[string]any)
	assert.NotEqual(t, "203.0.113.2", nested["ip"])
	assert.NotEqual(t, "nested.example.com", nested["domain"])
	moreNest := nested["more_nest"].(map[string]any)
	assert.NotEqual(t, "203.0.113.3", moreNest["ip"])
	assert.NotEqual(t, "deep.example.com", moreNest["domain"])

	// Arrays
	strArray := state["string_array"].([]any)
	assert.NotEqual(t, "203.0.113.4", strArray[0])
	assert.NotEqual(t, "test1.example.com", strArray[1])
	assert.True(t, strings.HasSuffix(strArray[1].(string), ".domain"))

	objArray := state["object_array"].([]any)
	firstObj := objArray[0].(map[string]any)
	assert.NotEqual(t, "203.0.113.5", firstObj["ip"])
	assert.NotEqual(t, "array1.example.com", firstObj["domain"])

	// Duplicate values should be anonymized consistently
	assert.Equal(t, state["public_ip"], state["duplicate_ip"])
	assert.Equal(t, state["domain"], state["duplicate_domain"])

	// URIs
	assert.NotContains(t, state["stun_uri"], "stun.example.com")
	assert.NotContains(t, state["turns_uri"], "turns.example.com")
	assert.NotContains(t, state["http_uri"], "web.example.com")
	assert.NotContains(t, state["https_uri"], "secure.example.com")

	// Non-IP strings should remain unchanged
	assert.Equal(t, "300.300.300.300", state["not_ip"])
	assert.Equal(t, "192.168", state["partial_ip"])
	assert.Equal(t, "1234.5678", state["ip_like_string"])

	// Mixed content should have IPs and domains replaced
	mixedContent := state["mixed_content"].(string)
	assert.NotContains(t, mixedContent, "203.0.113.1")
	assert.NotContains(t, mixedContent, "test.example.com")
	assert.Contains(t, mixedContent, "Server at ")
	assert.Contains(t, mixedContent, " on port 80")

	// Special values should remain unchanged
	assert.Equal(t, "", state["empty_string"])
	assert.Nil(t, state["null_value"])
	assert.Equal(t, float64(42), state["numeric_value"])
	assert.Equal(t, true, state["boolean_value"])

	// Check route state
	var routeState map[string]any
	err = json.Unmarshal(testState["route_state"], &routeState)
	require.NoError(t, err)

	routes := routeState["routes"].([]any)
	route1 := routes[0].(map[string]any)
	assert.NotEqual(t, "203.0.113.0/24", route1["network"])
	assert.Contains(t, route1["network"], "/24")
	assert.NotEqual(t, "203.0.113.1", route1["gateway"])
	domains := route1["domains"].([]any)
	assert.True(t, strings.HasSuffix(domains[0].(string), ".domain"))
	assert.True(t, strings.HasSuffix(domains[1].(string), ".domain"))

	// Check map keys are anonymized
	refCountMap := routeState["refCountMap"].(map[string]any)
	hasPublicIPKey := false
	hasIPv6Key := false
	hasPrivateIPKey := false
	for key := range refCountMap {
		if strings.Contains(key, "203.0.113.1") {
			hasPublicIPKey = true
		}
		if strings.Contains(key, "2001:db8::1") {
			hasIPv6Key = true
		}
		if key == "10.0.0.1/32" {
			hasPrivateIPKey = true
		}
	}
	assert.False(t, hasPublicIPKey, "public IP in key should be anonymized")
	assert.False(t, hasIPv6Key, "IPv6 in key should be anonymized")
	assert.True(t, hasPrivateIPKey, "private IP in key should remain unchanged")
}

func mustMarshal(v any) json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}

func TestAnonymizeNetworkMap(t *testing.T) {
	networkMap := &mgmProto.NetworkMap{
		PeerConfig: &mgmProto.PeerConfig{
			Address: "203.0.113.5",
			Dns:     "1.2.3.4",
			Fqdn:    "peer1.corp.example.com",
			SshConfig: &mgmProto.SSHConfig{
				SshPubKey: []byte("ssh-rsa AAAAB3NzaC1..."),
			},
		},
		RemotePeers: []*mgmProto.RemotePeerConfig{
			{
				AllowedIps: []string{
					"203.0.113.1/32",
					"2001:db8:1234::1/128",
					"192.168.1.1/32",
					"100.64.0.1/32",
					"10.0.0.1/32",
				},
				Fqdn: "peer2.corp.example.com",
				SshConfig: &mgmProto.SSHConfig{
					SshPubKey: []byte("ssh-rsa AAAAB3NzaC2..."),
				},
			},
		},
		Routes: []*mgmProto.Route{
			{
				Network: "197.51.100.0/24",
				Domains: []string{"prod.example.com", "staging.example.com"},
				NetID:   "net-123abc",
			},
		},
		DNSConfig: &mgmProto.DNSConfig{
			NameServerGroups: []*mgmProto.NameServerGroup{
				{
					NameServers: []*mgmProto.NameServer{
						{IP: "8.8.8.8"},
						{IP: "1.1.1.1"},
						{IP: "203.0.113.53"},
					},
					Domains: []string{"example.com", "internal.example.com"},
				},
			},
			CustomZones: []*mgmProto.CustomZone{
				{
					Domain: "custom.example.com",
					Records: []*mgmProto.SimpleRecord{
						{
							Name:  "www.custom.example.com",
							Type:  1,
							RData: "203.0.113.10",
						},
						{
							Name:  "internal.custom.example.com",
							Type:  1,
							RData: "192.168.1.10",
						},
					},
				},
			},
		},
	}

	// Create anonymizer with test addresses
	anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())

	// Anonymize the network map
	err := anonymizeNetworkMap(networkMap, anonymizer)
	require.NoError(t, err)

	// Test PeerConfig anonymization
	peerCfg := networkMap.PeerConfig
	require.NotEqual(t, "203.0.113.5", peerCfg.Address)

	// Verify DNS and FQDN are properly anonymized
	require.NotEqual(t, "1.2.3.4", peerCfg.Dns)
	require.NotEqual(t, "peer1.corp.example.com", peerCfg.Fqdn)
	require.True(t, strings.HasSuffix(peerCfg.Fqdn, ".domain"))

	// Verify SSH key is replaced
	require.Equal(t, []byte("ssh-placeholder-key"), peerCfg.SshConfig.SshPubKey)

	// Test RemotePeers anonymization
	remotePeer := networkMap.RemotePeers[0]

	// Verify FQDN is anonymized
	require.NotEqual(t, "peer2.corp.example.com", remotePeer.Fqdn)
	require.True(t, strings.HasSuffix(remotePeer.Fqdn, ".domain"))

	// Check that public IPs are anonymized but private IPs are preserved
	for _, allowedIP := range remotePeer.AllowedIps {
		ip, _, err := net.ParseCIDR(allowedIP)
		require.NoError(t, err)

		if ip.IsPrivate() || isInCGNATRange(ip) {
			require.Contains(t, []string{
				"192.168.1.1/32",
				"100.64.0.1/32",
				"10.0.0.1/32",
			}, allowedIP)
		} else {
			require.NotContains(t, []string{
				"203.0.113.1/32",
				"2001:db8:1234::1/128",
			}, allowedIP)
		}
	}

	// Test Routes anonymization
	route := networkMap.Routes[0]
	require.NotEqual(t, "197.51.100.0/24", route.Network)
	for _, domain := range route.Domains {
		require.True(t, strings.HasSuffix(domain, ".domain"))
		require.NotContains(t, domain, "example.com")
	}

	// Test DNS config anonymization
	dnsConfig := networkMap.DNSConfig
	nameServerGroup := dnsConfig.NameServerGroups[0]

	// Verify well-known DNS servers are preserved
	require.Equal(t, "8.8.8.8", nameServerGroup.NameServers[0].IP)
	require.Equal(t, "1.1.1.1", nameServerGroup.NameServers[1].IP)

	// Verify public DNS server is anonymized
	require.NotEqual(t, "203.0.113.53", nameServerGroup.NameServers[2].IP)

	// Verify domains are anonymized
	for _, domain := range nameServerGroup.Domains {
		require.True(t, strings.HasSuffix(domain, ".domain"))
		require.NotContains(t, domain, "example.com")
	}

	// Test CustomZones anonymization
	customZone := dnsConfig.CustomZones[0]
	require.True(t, strings.HasSuffix(customZone.Domain, ".domain"))
	require.NotContains(t, customZone.Domain, "example.com")

	// Verify records are properly anonymized
	for _, record := range customZone.Records {
		require.True(t, strings.HasSuffix(record.Name, ".domain"))
		require.NotContains(t, record.Name, "example.com")

		ip := net.ParseIP(record.RData)
		if ip != nil {
			if !ip.IsPrivate() {
				require.NotEqual(t, "203.0.113.10", record.RData)
			} else {
				require.Equal(t, "192.168.1.10", record.RData)
			}
		}
	}
}

// Helper function to check if IP is in CGNAT range
func isInCGNATRange(ip net.IP) bool {
	cgnat := net.IPNet{
		IP:   net.ParseIP("100.64.0.0"),
		Mask: net.CIDRMask(10, 32),
	}
	return cgnat.Contains(ip)
}

func TestAnonymizeFirewallRules(t *testing.T) {
	// TODO: Add ipv6

	// Example iptables-save output
	iptablesSave := `# Generated by iptables-save v1.8.7 on Thu Dec 19 10:00:00 2024
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -s 192.168.1.0/24 -j ACCEPT
-A INPUT -s 44.192.140.1/32 -j DROP
-A FORWARD -s 10.0.0.0/8 -j DROP
-A FORWARD -s 44.192.140.0/24 -d 52.84.12.34/24 -j ACCEPT
COMMIT

*nat
:PREROUTING ACCEPT [0:0]
:INPUT ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 192.168.100.0/24 -j MASQUERADE
-A PREROUTING -d 44.192.140.10/32 -p tcp -m tcp --dport 80 -j DNAT --to-destination 192.168.1.10:80
COMMIT`

	// Example iptables -v -n -L output
	iptablesVerbose := `Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
    pkts bytes target     prot opt in     out     source               destination         
       0     0 ACCEPT     all  --  *      *       192.168.1.0/24       0.0.0.0/0           
     100  1024 DROP       all  --  *      *       44.192.140.1         0.0.0.0/0

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
    pkts bytes target     prot opt in     out     source               destination         
       0     0 DROP       all  --  *      *       10.0.0.0/8           0.0.0.0/0           
      25   256 ACCEPT     all  --  *      *       44.192.140.0/24      52.84.12.34/24

Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
    pkts bytes target     prot opt in     out     source               destination`

	// Example nftables output
	nftablesRules := `table inet filter {
        chain input {
                type filter hook input priority filter; policy accept;
                ip saddr 192.168.1.1 accept
                ip saddr 44.192.140.1 drop
        }
        chain forward {
                type filter hook forward priority filter; policy accept;
                ip saddr 10.0.0.0/8 drop
                ip saddr 44.192.140.0/24 ip daddr 52.84.12.34/24 accept
        }
    }`

	anonymizer := anonymize.NewAnonymizer(anonymize.DefaultAddresses())

	// Test iptables-save anonymization
	anonIptablesSave := anonymizer.AnonymizeString(iptablesSave)

	// Private IP addresses should remain unchanged
	assert.Contains(t, anonIptablesSave, "192.168.1.0/24")
	assert.Contains(t, anonIptablesSave, "10.0.0.0/8")
	assert.Contains(t, anonIptablesSave, "192.168.100.0/24")
	assert.Contains(t, anonIptablesSave, "192.168.1.10")

	// Public IP addresses should be anonymized to the default range
	assert.NotContains(t, anonIptablesSave, "44.192.140.1")
	assert.NotContains(t, anonIptablesSave, "44.192.140.0/24")
	assert.NotContains(t, anonIptablesSave, "52.84.12.34")
	assert.Contains(t, anonIptablesSave, "198.51.100.") // Default anonymous range

	// Structure should be preserved
	assert.Contains(t, anonIptablesSave, "*filter")
	assert.Contains(t, anonIptablesSave, ":INPUT ACCEPT [0:0]")
	assert.Contains(t, anonIptablesSave, "COMMIT")
	assert.Contains(t, anonIptablesSave, "-j MASQUERADE")
	assert.Contains(t, anonIptablesSave, "--dport 80")

	// Test iptables verbose output anonymization
	anonIptablesVerbose := anonymizer.AnonymizeString(iptablesVerbose)

	// Private IP addresses should remain unchanged
	assert.Contains(t, anonIptablesVerbose, "192.168.1.0/24")
	assert.Contains(t, anonIptablesVerbose, "10.0.0.0/8")

	// Public IP addresses should be anonymized to the default range
	assert.NotContains(t, anonIptablesVerbose, "44.192.140.1")
	assert.NotContains(t, anonIptablesVerbose, "44.192.140.0/24")
	assert.NotContains(t, anonIptablesVerbose, "52.84.12.34")
	assert.Contains(t, anonIptablesVerbose, "198.51.100.") // Default anonymous range

	// Structure and counters should be preserved
	assert.Contains(t, anonIptablesVerbose, "Chain INPUT (policy ACCEPT 0 packets, 0 bytes)")
	assert.Contains(t, anonIptablesVerbose, "100  1024 DROP")
	assert.Contains(t, anonIptablesVerbose, "pkts bytes target")

	// Test nftables anonymization
	anonNftables := anonymizer.AnonymizeString(nftablesRules)

	// Private IP addresses should remain unchanged
	assert.Contains(t, anonNftables, "192.168.1.1")
	assert.Contains(t, anonNftables, "10.0.0.0/8")

	// Public IP addresses should be anonymized to the default range
	assert.NotContains(t, anonNftables, "44.192.140.1")
	assert.NotContains(t, anonNftables, "44.192.140.0/24")
	assert.NotContains(t, anonNftables, "52.84.12.34")
	assert.Contains(t, anonNftables, "198.51.100.") // Default anonymous range

	// Structure should be preserved
	assert.Contains(t, anonNftables, "table inet filter {")
	assert.Contains(t, anonNftables, "chain input {")
	assert.Contains(t, anonNftables, "type filter hook input priority filter; policy accept;")
}
