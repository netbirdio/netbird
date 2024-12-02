package server

import (
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/anonymize"
	mgmProto "github.com/netbirdio/netbird/management/proto"
)

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
