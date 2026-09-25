package legacynmap

import (
	nbdns "github.com/netbirdio/netbird/dns"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/route"
)

// NetworkMap is main's shape. It is copied rather than aliased because this
// branch's NetworkMap dropped ForceRoutingPeerDNSResolution, which main threads
// into PeerConfig.RoutingPeerDnsResolutionEnabled.
type NetworkMap struct {
	Peers               []*ComponentPeer
	Network             *Network
	Routes              []*route.Route
	DNSConfig           nbdns.Config
	OfflinePeers        []*ComponentPeer
	FirewallRules       []*FirewallRule
	RoutesFirewallRules []*RouteFirewallRule
	ForwardingRules     []*ForwardingRule
	AuthorizedUsers     map[string]map[string]struct{}
	EnableSSH           bool
	// ForceRoutingPeerDNSResolution forces the peer to run/use routing-peer DNS
	// resolution regardless of the account-global setting, for reverse-proxy
	// domain targets.
	ForceRoutingPeerDNSResolution bool
}

// The ToComponent converters below are main's methods, re-expressed as free
// functions because their receivers live in packages this one cannot extend.
// Bodies are otherwise unchanged.

func peerToComponent(p *nbpeer.Peer) *ComponentPeer {
	if p == nil {
		return nil
	}
	cp := &ComponentPeer{
		ID:                     p.ID,
		Key:                    p.Key,
		IP:                     p.IP,
		IPv6:                   p.IPv6,
		DNSLabel:               p.DNSLabel,
		SSHKey:                 p.SSHKey,
		SSHEnabled:             p.SSHEnabled,
		ServerSSHAllowed:       p.Meta.Flags.ServerSSHAllowed,
		AgentVersion:           p.Meta.WtVersion,
		SupportsSourcePrefixes: p.SupportsSourcePrefixes(),
		SupportsIPv6:           p.SupportsIPv6(),
		LoginExpirationEnabled: p.LoginExpirationEnabled,
		AddedWithSSOLogin:      p.AddedWithSSOLogin(),
		ProxyEmbedded:          p.ProxyMeta.Embedded,
	}
	if p.LastLogin != nil {
		cp.LastLogin = *p.LastLogin
	}
	return cp
}

func groupToComponent(g *Group) *ComponentGroup {
	if g == nil {
		return nil
	}
	return &ComponentGroup{
		ID:       g.ID,
		PublicID: g.PublicID,
		Name:     g.Name,
		Peers:    g.Peers,
	}
}

func groupsToComponent(groups map[string]*Group) map[string]*ComponentGroup {
	if groups == nil {
		return nil
	}
	out := make(map[string]*ComponentGroup, len(groups))
	for id, g := range groups {
		out[id] = groupToComponent(g)
	}
	return out
}

func routerToComponent(n *routerTypes.NetworkRouter) *ComponentRouter {
	if n == nil {
		return nil
	}
	return &ComponentRouter{
		NetworkID:  n.NetworkID,
		PublicID:   n.PublicID,
		Peer:       n.Peer,
		PeerGroups: n.PeerGroups,
		Masquerade: n.Masquerade,
		Metric:     n.Metric,
		Enabled:    n.Enabled,
	}
}

func routersToComponentMap(routers map[string]*routerTypes.NetworkRouter) map[string]*ComponentRouter {
	if routers == nil {
		return nil
	}
	out := make(map[string]*ComponentRouter, len(routers))
	for id, r := range routers {
		out[id] = routerToComponent(r)
	}
	return out
}

func resourceToComponent(n *resourceTypes.NetworkResource) *ComponentResource {
	if n == nil {
		return nil
	}
	return &ComponentResource{
		ID:          n.ID,
		PublicID:    n.PublicID,
		NetworkID:   n.NetworkID,
		AccountID:   n.AccountID,
		Name:        n.Name,
		Description: n.Description,
		Type:        ComponentResourceType(n.Type),
		Address:     n.Address,
		Domain:      n.Domain,
		Prefix:      n.Prefix,
		Enabled:     n.Enabled,
	}
}
