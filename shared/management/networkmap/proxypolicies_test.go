package networkmap_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

func TestInjectProxyPolicies_PortMappings(t *testing.T) {
	proxyPeer := newPeer("proxy-peer", 1)
	proxyPeer.ProxyMeta = nmdata.ProxyMeta{Embedded: true, Cluster: "proxy.example.test"}
	nmd := newNMD(proxyPeer, newPeer("target-peer", 2))
	nmd.Services = []*nmdata.Service{{
		ID: "service-1", Enabled: true, ProxyCluster: "proxy.example.test",
		Targets: []*nmdata.ServiceTarget{{Enabled: true, TargetID: "target-peer", TargetType: "peer"}},
		PortMappings: []*nmdata.PortMapping{
			{Protocol: "tcp", TargetPortStart: 443, TargetPortEnd: 443},
			{Protocol: "udp", TargetPortStart: 7443, TargetPortEnd: 7443},
			{Protocol: "tcp", TargetPortStart: 6000, TargetPortEnd: 6030},
		},
	}}

	nmd.InjectProxyPolicies()

	require.Len(t, nmd.Policies, 1)
	policy := nmd.Policies[0]
	require.Len(t, policy.Rules, 3)
	assert.Equal(t, []string{
		"proxy-access-service-1-proxy-peer--mapping-0",
		"proxy-access-service-1-proxy-peer--mapping-1",
		"proxy-access-service-1-proxy-peer--mapping-2",
	}, []string{policy.Rules[0].ID, policy.Rules[1].ID, policy.Rules[2].ID})
	assert.Equal(t, []string{"tcp", "udp", "tcp"}, []string{policy.Rules[0].Protocol, policy.Rules[1].Protocol, policy.Rules[2].Protocol})
	assert.Equal(t, []nmdata.RulePortRange{{Start: 443, End: 443}}, policy.Rules[0].PortRanges)
	assert.Equal(t, []nmdata.RulePortRange{{Start: 7443, End: 7443}}, policy.Rules[1].PortRanges)
	assert.Equal(t, []nmdata.RulePortRange{{Start: 6000, End: 6030}}, policy.Rules[2].PortRanges)
}

func TestInjectProxyPolicies_UsesTargetPortWithoutPortMappings(t *testing.T) {
	proxyPeer := newPeer("proxy-peer", 1)
	proxyPeer.ProxyMeta = nmdata.ProxyMeta{Embedded: true, Cluster: "proxy.example.test"}
	nmd := newNMD(proxyPeer, newPeer("target-peer", 2))
	nmd.Services = []*nmdata.Service{{
		ID: "legacy", Enabled: true, Mode: "udp", ProxyCluster: "proxy.example.test",
		Targets: []*nmdata.ServiceTarget{{Enabled: true, TargetID: "target-peer", TargetType: "peer", Port: 53}},
	}}

	nmd.InjectProxyPolicies()

	require.Len(t, nmd.Policies, 1)
	require.Len(t, nmd.Policies[0].Rules, 1)
	assert.Equal(t, "udp", nmd.Policies[0].Rules[0].Protocol)
	assert.Equal(t, []nmdata.RulePortRange{{Start: 53, End: 53}}, nmd.Policies[0].Rules[0].PortRanges)
}
