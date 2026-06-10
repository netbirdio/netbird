package types

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

func TestPrivateService_NetworkMap_UserPeer_AndProxyPeer(t *testing.T) {
	account := privateZoneTestAccount(t)
	account.Peers["user-peer"].Meta.WtVersion = "0.50.0"
	account.Peers["proxy-peer"].Meta.WtVersion = "0.50.0"

	ctx := context.Background()
	account.InjectProxyPolicies(ctx)

	validated := map[string]struct{}{
		"user-peer":  {},
		"proxy-peer": {},
	}

	t.Run("user-peer update", func(t *testing.T) {
		nm := account.GetPeerNetworkMapFromComponents(ctx, "user-peer", nbdns.CustomZone{}, nil, validated, nil, nil, nil, nil)
		require.NotNil(t, nm)

		zone, ok := findCustomZone(nm.DNSConfig.CustomZones, "eu.proxy.netbird.io")
		require.True(t, ok)
		require.Len(t, zone.Records, 1)
		assert.Equal(t, "myapp.eu.proxy.netbird.io.", zone.Records[0].Name)
		assert.Equal(t, int(dns.TypeA), zone.Records[0].Type)
		assert.Equal(t, "100.64.0.99", zone.Records[0].RData)

		assert.Contains(t, netmapPeerIDs(nm.Peers), "proxy-peer")
		assertPrivateServiceFirewallRules(t, nm.FirewallRules, "100.64.0.99", FirewallRuleDirectionOUT)
	})

	t.Run("proxy-peer update", func(t *testing.T) {
		nm := account.GetPeerNetworkMapFromComponents(ctx, "proxy-peer", nbdns.CustomZone{}, nil, validated, nil, nil, nil, nil)
		require.NotNil(t, nm)

		assert.Contains(t, netmapPeerIDs(nm.Peers), "user-peer")
		assertPrivateServiceFirewallRules(t, nm.FirewallRules, "100.64.0.10", FirewallRuleDirectionIN)
	})
}

func netmapPeerIDs(peers []*nbpeer.Peer) []string {
	ids := make([]string, 0, len(peers))
	for _, p := range peers {
		if p == nil {
			continue
		}
		ids = append(ids, p.ID)
	}
	return ids
}

func assertPrivateServiceFirewallRules(t *testing.T, rules []*FirewallRule, peerIP string, direction int) {
	t.Helper()
	wantPorts := map[uint16]bool{80: false, 443: false}
	for _, r := range rules {
		if r == nil || r.PeerIP != peerIP || r.Direction != direction {
			continue
		}
		if r.Protocol != string(PolicyRuleProtocolTCP) || r.Action != string(PolicyTrafficActionAccept) {
			continue
		}
		switch {
		case r.PortRange.Start == r.PortRange.End && r.PortRange.Start != 0:
			wantPorts[r.PortRange.Start] = true
		case r.Port == "80":
			wantPorts[80] = true
		case r.Port == "443":
			wantPorts[443] = true
		}
	}
	for port, found := range wantPorts {
		assert.Truef(t, found, "missing TCP accept rule on port %d for peer %s direction %d", port, peerIP, direction)
	}
}
