package types

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/reverseproxy"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
)

func TestGetProxyConnectionResources_PeerTarget(t *testing.T) {
	account := &Account{
		Peers: map[string]*nbpeer.Peer{
			"target-peer": {ID: "target-peer", IP: net.ParseIP("100.64.0.1")},
		},
	}

	exposedServices := map[string][]*reverseproxy.ReverseProxy{
		"target-peer": {
			{
				ID:      "proxy-1",
				Enabled: true,
				Targets: []reverseproxy.Target{
					{
						TargetType: reverseproxy.TargetTypePeer,
						TargetId:   "target-peer",
						Port:       8080,
						Enabled:    true,
					},
				},
			},
		},
	}

	aclPeers := account.GetProxyConnectionResources(context.Background(), exposedServices)

	require.Len(t, aclPeers, 1)
	assert.Equal(t, "target-peer", aclPeers[0].ID)
}

func TestGetProxyConnectionResources_DisabledService(t *testing.T) {
	account := &Account{
		Peers: map[string]*nbpeer.Peer{
			"target-peer": {ID: "target-peer", IP: net.ParseIP("100.64.0.1")},
		},
	}

	exposedServices := map[string][]*reverseproxy.ReverseProxy{
		"target-peer": {
			{
				ID:      "proxy-1",
				Enabled: false,
				Targets: []reverseproxy.Target{
					{
						TargetType: reverseproxy.TargetTypePeer,
						TargetId:   "target-peer",
						Port:       8080,
						Enabled:    true,
					},
				},
			},
		},
	}

	aclPeers := account.GetProxyConnectionResources(context.Background(), exposedServices)
	assert.Empty(t, aclPeers)
}

func TestGetProxyConnectionResources_ResourceTargetSkipped(t *testing.T) {
	account := &Account{
		Peers: map[string]*nbpeer.Peer{
			"router-peer": {ID: "router-peer", IP: net.ParseIP("100.64.0.2")},
		},
	}

	exposedServices := map[string][]*reverseproxy.ReverseProxy{
		"router-peer": {
			{
				ID:      "proxy-1",
				Enabled: true,
				Targets: []reverseproxy.Target{
					{
						TargetType: reverseproxy.TargetTypeResource,
						TargetId:   "resource-1",
						Port:       443,
						Enabled:    true,
					},
				},
			},
		},
	}

	aclPeers := account.GetProxyConnectionResources(context.Background(), exposedServices)
	assert.Empty(t, aclPeers, "resource targets should not add ACL peers via GetProxyConnectionResources")
}

func TestGetPeerProxyResources_PeerTarget(t *testing.T) {
	proxyPeers := []*nbpeer.Peer{
		{ID: "proxy-peer-1", IP: net.ParseIP("100.64.0.10")},
		{ID: "proxy-peer-2", IP: net.ParseIP("100.64.0.11")},
	}

	services := []*reverseproxy.ReverseProxy{
		{
			ID:      "proxy-1",
			Enabled: true,
			Targets: []reverseproxy.Target{
				{
					TargetType: reverseproxy.TargetTypePeer,
					TargetId:   "target-peer",
					Port:       8080,
					Enabled:    true,
				},
			},
		},
	}

	account := &Account{}
	aclPeers, fwRules := account.GetPeerProxyResources("target-peer", services, proxyPeers)

	require.Len(t, aclPeers, 2, "should include all proxy peers")
	require.Len(t, fwRules, 2, "should have one IN rule per proxy peer")

	for i, rule := range fwRules {
		assert.Equal(t, "proxy-proxy-1", rule.PolicyID)
		assert.Equal(t, proxyPeers[i].IP.String(), rule.PeerIP)
		assert.Equal(t, FirewallRuleDirectionIN, rule.Direction)
		assert.Equal(t, "allow", rule.Action)
		assert.Equal(t, string(PolicyRuleProtocolTCP), rule.Protocol)
		assert.Equal(t, uint16(8080), rule.PortRange.Start)
		assert.Equal(t, uint16(8080), rule.PortRange.End)
	}
}

func TestGetPeerProxyResources_PeerTargetMismatch(t *testing.T) {
	proxyPeers := []*nbpeer.Peer{
		{ID: "proxy-peer-1", IP: net.ParseIP("100.64.0.10")},
	}

	services := []*reverseproxy.ReverseProxy{
		{
			ID:      "proxy-1",
			Enabled: true,
			Targets: []reverseproxy.Target{
				{
					TargetType: reverseproxy.TargetTypePeer,
					TargetId:   "other-peer",
					Port:       8080,
					Enabled:    true,
				},
			},
		},
	}

	account := &Account{}
	aclPeers, fwRules := account.GetPeerProxyResources("target-peer", services, proxyPeers)

	require.Len(t, aclPeers, 1, "should still add proxy peers to ACL")
	assert.Empty(t, fwRules, "should not generate rules when target doesn't match this peer")
}

func TestGetPeerProxyResources_ResourceAccessLocal(t *testing.T) {
	proxyPeers := []*nbpeer.Peer{
		{ID: "proxy-peer-1", IP: net.ParseIP("100.64.0.10")},
	}

	services := []*reverseproxy.ReverseProxy{
		{
			ID:      "proxy-1",
			Enabled: true,
			Targets: []reverseproxy.Target{
				{
					TargetType:  reverseproxy.TargetTypeResource,
					TargetId:    "resource-1",
					Port:        443,
					Enabled:     true,
					AccessLocal: true,
				},
			},
		},
	}

	account := &Account{}
	aclPeers, fwRules := account.GetPeerProxyResources("router-peer", services, proxyPeers)

	require.Len(t, aclPeers, 1, "should include proxy peers in ACL")
	require.Len(t, fwRules, 1, "should generate IN rule for AccessLocal resource")

	rule := fwRules[0]
	assert.Equal(t, "proxy-proxy-1", rule.PolicyID)
	assert.Equal(t, "100.64.0.10", rule.PeerIP)
	assert.Equal(t, FirewallRuleDirectionIN, rule.Direction)
	assert.Equal(t, uint16(443), rule.PortRange.Start)
}

func TestGetPeerProxyResources_ResourceWithoutAccessLocal(t *testing.T) {
	proxyPeers := []*nbpeer.Peer{
		{ID: "proxy-peer-1", IP: net.ParseIP("100.64.0.10")},
	}

	services := []*reverseproxy.ReverseProxy{
		{
			ID:      "proxy-1",
			Enabled: true,
			Targets: []reverseproxy.Target{
				{
					TargetType:  reverseproxy.TargetTypeResource,
					TargetId:    "resource-1",
					Port:        443,
					Enabled:     true,
					AccessLocal: false,
				},
			},
		},
	}

	account := &Account{}
	aclPeers, fwRules := account.GetPeerProxyResources("router-peer", services, proxyPeers)

	require.Len(t, aclPeers, 1, "should still include proxy peers in ACL")
	assert.Empty(t, fwRules, "should not generate peer rules when AccessLocal is false")
}

func TestGetPeerProxyResources_MixedTargets(t *testing.T) {
	proxyPeers := []*nbpeer.Peer{
		{ID: "proxy-peer-1", IP: net.ParseIP("100.64.0.10")},
	}

	services := []*reverseproxy.ReverseProxy{
		{
			ID:      "proxy-1",
			Enabled: true,
			Targets: []reverseproxy.Target{
				{
					TargetType: reverseproxy.TargetTypePeer,
					TargetId:   "target-peer",
					Port:       8080,
					Enabled:    true,
				},
				{
					TargetType:  reverseproxy.TargetTypeResource,
					TargetId:    "resource-1",
					Port:        443,
					Enabled:     true,
					AccessLocal: true,
				},
				{
					TargetType:  reverseproxy.TargetTypeResource,
					TargetId:    "resource-2",
					Port:        8443,
					Enabled:     true,
					AccessLocal: false,
				},
			},
		},
	}

	account := &Account{}
	aclPeers, fwRules := account.GetPeerProxyResources("target-peer", services, proxyPeers)

	require.Len(t, aclPeers, 1)
	require.Len(t, fwRules, 2, "should have rules for peer target + AccessLocal resource")

	ports := []uint16{fwRules[0].PortRange.Start, fwRules[1].PortRange.Start}
	assert.Contains(t, ports, uint16(8080), "should include peer target port")
	assert.Contains(t, ports, uint16(443), "should include AccessLocal resource port")
}

func newProxyRoutesTestAccount() *Account {
	return &Account{
		Peers: map[string]*nbpeer.Peer{
			"router-peer": {ID: "router-peer", Key: "router-key", IP: net.ParseIP("100.64.0.2")},
			"proxy-peer":  {ID: "proxy-peer", Key: "proxy-key", IP: net.ParseIP("100.64.0.10")},
		},
	}
}

func TestGetPeerProxyRoutes_ResourceWithoutAccessLocal(t *testing.T) {
	account := newProxyRoutesTestAccount()
	proxyPeers := []*nbpeer.Peer{account.Peers["proxy-peer"]}

	resourcesMap := map[string]*resourceTypes.NetworkResource{
		"resource-1": {
			ID:        "resource-1",
			AccountID: "accountID",
			NetworkID: "net-1",
			Name:      "web-service",
			Type:      resourceTypes.Host,
			Prefix:    netip.MustParsePrefix("192.168.1.100/32"),
			Enabled:   true,
		},
	}
	routers := map[string]map[string]*routerTypes.NetworkRouter{
		"net-1": {
			"router-peer": {ID: "router-1", NetworkID: "net-1", Peer: "router-peer", Masquerade: true, Metric: 100},
		},
	}

	exposedServices := map[string][]*reverseproxy.ReverseProxy{
		"router-peer": {
			{
				ID:      "proxy-1",
				Enabled: true,
				Targets: []reverseproxy.Target{
					{
						TargetType:  reverseproxy.TargetTypeResource,
						TargetId:    "resource-1",
						Port:        443,
						Enabled:     true,
						AccessLocal: false,
					},
				},
			},
		},
	}

	routes, routeFwRules, aclPeers := account.GetPeerProxyRoutes(context.Background(), account.Peers["proxy-peer"], exposedServices, resourcesMap, routers, proxyPeers)

	require.NotEmpty(t, routes, "should generate routes for non-AccessLocal resource")
	require.NotEmpty(t, routeFwRules, "should generate route firewall rules for non-AccessLocal resource")
	require.NotEmpty(t, aclPeers, "should include router peer in ACL")

	assert.Equal(t, uint16(443), routeFwRules[0].PortRange.Start)
	assert.Equal(t, "192.168.1.100/32", routeFwRules[0].Destination)
}

func TestGetPeerProxyRoutes_ResourceWithAccessLocal(t *testing.T) {
	account := newProxyRoutesTestAccount()
	proxyPeers := []*nbpeer.Peer{account.Peers["proxy-peer"]}

	resourcesMap := map[string]*resourceTypes.NetworkResource{
		"resource-1": {
			ID:        "resource-1",
			AccountID: "accountID",
			NetworkID: "net-1",
			Name:      "local-service",
			Type:      resourceTypes.Host,
			Prefix:    netip.MustParsePrefix("192.168.1.100/32"),
			Enabled:   true,
		},
	}
	routers := map[string]map[string]*routerTypes.NetworkRouter{
		"net-1": {
			"router-peer": {ID: "router-1", NetworkID: "net-1", Peer: "router-peer", Masquerade: true, Metric: 100},
		},
	}

	exposedServices := map[string][]*reverseproxy.ReverseProxy{
		"router-peer": {
			{
				ID:      "proxy-1",
				Enabled: true,
				Targets: []reverseproxy.Target{
					{
						TargetType:  reverseproxy.TargetTypeResource,
						TargetId:    "resource-1",
						Port:        443,
						Enabled:     true,
						AccessLocal: true,
					},
				},
			},
		},
	}

	routes, routeFwRules, aclPeers := account.GetPeerProxyRoutes(context.Background(), account.Peers["proxy-peer"], exposedServices, resourcesMap, routers, proxyPeers)

	assert.Empty(t, routes, "should NOT generate routes for AccessLocal resource")
	assert.Empty(t, routeFwRules, "should NOT generate route firewall rules for AccessLocal resource")
	assert.Empty(t, aclPeers, "should NOT include router peer from route path for AccessLocal resource")
}

func TestGetPeerProxyRoutes_PeerTargetSkipped(t *testing.T) {
	account := newProxyRoutesTestAccount()
	proxyPeers := []*nbpeer.Peer{account.Peers["proxy-peer"]}

	exposedServices := map[string][]*reverseproxy.ReverseProxy{
		"router-peer": {
			{
				ID:      "proxy-1",
				Enabled: true,
				Targets: []reverseproxy.Target{
					{
						TargetType: reverseproxy.TargetTypePeer,
						TargetId:   "target-peer",
						Port:       8080,
						Enabled:    true,
					},
				},
			},
		},
	}

	routes, routeFwRules, aclPeers := account.GetPeerProxyRoutes(context.Background(), account.Peers["proxy-peer"], exposedServices, nil, nil, proxyPeers)

	assert.Empty(t, routes, "should NOT generate routes for peer targets")
	assert.Empty(t, routeFwRules, "should NOT generate route firewall rules for peer targets")
	assert.Empty(t, aclPeers)
}
