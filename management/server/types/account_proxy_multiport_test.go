package types

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

func TestInjectProxyPolicies_MultiPortTargetRanges(t *testing.T) {
	account := &Account{
		Id: "account-1",
		Peers: map[string]*nbpeer.Peer{
			"proxy-peer": {
				ID: "proxy-peer",
				ProxyMeta: nbpeer.ProxyMeta{
					Embedded: true,
					Cluster:  "proxy.example.test",
				},
			},
			"target-peer": {ID: "target-peer"},
		},
		Services: []*rpservice.Service{{
			ID: "service-1", Name: "game", Domain: "game.proxy.example.test",
			ProxyCluster: "proxy.example.test", Mode: rpservice.ModeTCP,
			ListenPort: 443, Enabled: true,
			Targets: []*rpservice.Target{{
				TargetId: "target-peer", TargetType: rpservice.TargetTypePeer,
				Protocol: rpservice.TargetProtoTCP, Port: 443, Enabled: true,
			}},
			PortMappings: []*rpservice.PortMapping{
				{Protocol: rpservice.ModeTCP, ListenPortStart: 443, ListenPortEnd: 443, TargetPortStart: 443, TargetPortEnd: 443},
				{Protocol: rpservice.ModeUDP, ListenPortStart: 443, ListenPortEnd: 443, TargetPortStart: 7443, TargetPortEnd: 7443},
				{Protocol: rpservice.ModeTCP, ListenPortStart: 5000, ListenPortEnd: 5030, TargetPortStart: 6000, TargetPortEnd: 6030},
				{Protocol: rpservice.ModeUDP, ListenPortStart: 7000, ListenPortEnd: 7002, TargetPortStart: 9000, TargetPortEnd: 9002},
			},
		}},
	}

	policies := injectedPolicies(account)
	require.Len(t, policies, 1)
	policy := policies[0]
	assert.Equal(t, "proxy-access-service-1-proxy-peer-", policy.ID)
	require.Len(t, policy.Rules, 4)

	expected := []struct {
		protocol string
		start    uint16
		end      uint16
	}{
		{string(PolicyRuleProtocolTCP), 443, 443},
		{string(PolicyRuleProtocolUDP), 7443, 7443},
		{string(PolicyRuleProtocolTCP), 6000, 6030},
		{string(PolicyRuleProtocolUDP), 9000, 9002},
	}
	for i, rule := range policy.Rules {
		assert.Equal(t, policy.ID, rule.PolicyID)
		assert.Equal(t, fmt.Sprintf("%s-mapping-%d", policy.ID, i), rule.ID)
		assert.Equal(t, expected[i].protocol, rule.Protocol)
		require.Len(t, rule.PortRanges, 1)
		assert.Equal(t, expected[i].start, rule.PortRanges[0].Start)
		assert.Equal(t, expected[i].end, rule.PortRanges[0].End)
		assert.Equal(t, "proxy-peer", rule.SourceResource.ID)
		assert.Equal(t, "target-peer", rule.DestinationResource.ID)
	}
}

func TestInjectProxyPolicies_LegacyScalarFallback(t *testing.T) {
	account := &Account{
		Peers: map[string]*nbpeer.Peer{
			"proxy-peer": {
				ID:        "proxy-peer",
				ProxyMeta: nbpeer.ProxyMeta{Embedded: true, Cluster: "proxy.example.test"},
			},
		},
		Services: []*rpservice.Service{{
			ID: "legacy", Name: "dns", ProxyCluster: "proxy.example.test",
			Mode: rpservice.ModeUDP, ListenPort: 15353, Enabled: true,
			Targets: []*rpservice.Target{{
				TargetId: "target-peer", TargetType: rpservice.TargetTypePeer,
				Protocol: rpservice.TargetProtoUDP, Port: 53, Enabled: true,
			}},
		}},
	}

	policies := injectedPolicies(account)
	require.Len(t, policies, 1)
	require.Len(t, policies[0].Rules, 1)
	rule := policies[0].Rules[0]
	assert.Equal(t, policies[0].ID, rule.ID)
	assert.Equal(t, string(PolicyRuleProtocolUDP), rule.Protocol)
	require.Len(t, rule.PortRanges, 1)
	assert.Equal(t, uint16(53), rule.PortRanges[0].Start)
	assert.Equal(t, uint16(53), rule.PortRanges[0].End)
}
