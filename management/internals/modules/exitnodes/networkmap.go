package exitnodes

import (
	"net/netip"
	"slices"

	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
)

// exitPrefix is the destination of the network resource an exit node is sent as.
var exitPrefix = netip.MustParsePrefix("0.0.0.0/0")

// networkObjects is an exit node in the shape clients already understand: a network holding
// one 0.0.0.0/0 subnet resource, routed by the exit node peers. The network and the resource
// take the exit node ID, so policies whose destination resource is the exit node apply to
// the resource without being rewritten.
type networkObjects struct {
	network  *networkTypes.Network
	resource *resourceTypes.NetworkResource
	routers  []*routerTypes.NetworkRouter
}

// toNetworkObjects returns false when the exit node is disabled or has no enabled peer,
// as it then routes nothing.
func (e *ExitNode) toNetworkObjects() (networkObjects, bool) {
	if !e.Enabled {
		return networkObjects{}, false
	}

	id := string(e.ID)
	var routers []*routerTypes.NetworkRouter
	for _, p := range e.Peers {
		if !p.Enabled {
			continue
		}
		routers = append(routers, &routerTypes.NetworkRouter{
			ID:         id + ":" + p.PeerID,
			NetworkID:  id,
			AccountID:  e.AccountID,
			PublicID:   p.PublicID,
			Peer:       p.PeerID,
			Masquerade: true,
			Metric:     p.Metric,
			Enabled:    true,
		})
	}
	if len(routers) == 0 {
		return networkObjects{}, false
	}

	return networkObjects{
		network: &networkTypes.Network{
			ID:          id,
			AccountID:   e.AccountID,
			PublicID:    e.PublicID,
			Name:        e.Name,
			Description: e.Description,
		},
		resource: &resourceTypes.NetworkResource{
			ID:          id,
			NetworkID:   id,
			AccountID:   e.AccountID,
			PublicID:    e.PublicID,
			Name:        e.Name,
			Description: e.Description,
			Type:        resourceTypes.Subnet,
			Prefix:      exitPrefix,
			Enabled:     true,
		},
		routers: routers,
	}, true
}

// InjectIntoAccount adds the exit nodes to the account as networks, resources and routers,
// so the network map built from the account routes internet traffic through them. Call it
// before the resource policies and routers maps are derived from the account. The slices
// are replaced, not appended to, because the account may be a shallow copy sharing them.
func InjectIntoAccount(account *types.Account, exitNodes []*ExitNode) {
	var networks []*networkTypes.Network
	var resources []*resourceTypes.NetworkResource
	var routers []*routerTypes.NetworkRouter
	for _, node := range exitNodes {
		objects, ok := node.toNetworkObjects()
		if !ok {
			continue
		}
		networks = append(networks, objects.network)
		resources = append(resources, objects.resource)
		routers = append(routers, objects.routers...)
	}
	if len(resources) == 0 {
		return
	}

	account.Networks = slices.Concat(account.Networks, networks)
	account.NetworkResources = slices.Concat(account.NetworkResources, resources)
	account.NetworkRouters = slices.Concat(account.NetworkRouters, routers)
}

// InjectIntoNetworkMapData adds the exit nodes to the network map data as network resources
// with their routers and the policies whose destination is the exit node. Call it before
// the data is shared.
func InjectIntoNetworkMapData(nmd *networkmap.NetworkMapData, exitNodes []*ExitNode) {
	for _, node := range exitNodes {
		objects, ok := node.toNetworkObjects()
		if !ok {
			continue
		}
		id := objects.resource.ID

		if nmd.NetworkXIDToPublicID == nil {
			nmd.NetworkXIDToPublicID = make(map[string]string)
		}
		nmd.NetworkXIDToPublicID[id] = objects.network.PublicID

		resource := types.TwinNetworkResource(objects.resource)
		resource.SkipAutoApply = !node.AutoApply
		nmd.NetworkResources = append(nmd.NetworkResources, resource)

		if nmd.Routers == nil {
			nmd.Routers = make(map[string]map[string]*nmdata.NetworkRouter)
		}
		routers := make(map[string]*nmdata.NetworkRouter, len(objects.routers))
		for _, r := range objects.routers {
			routers[r.Peer] = &nmdata.NetworkRouter{
				PublicID:   r.PublicID,
				Masquerade: r.Masquerade,
				Metric:     r.Metric,
				Enabled:    r.Enabled,
			}
		}
		nmd.Routers[id] = routers

		if policies := policiesTargeting(nmd.Policies, id); len(policies) > 0 {
			if nmd.ResourcePolicies == nil {
				nmd.ResourcePolicies = make(map[string][]*nmdata.Policy)
			}
			nmd.ResourcePolicies[id] = policies
		}
	}
}

// policiesTargeting returns the enabled policies with an enabled rule whose destination is
// the exit node.
func policiesTargeting(policies []*nmdata.Policy, exitNodeID string) []*nmdata.Policy {
	var out []*nmdata.Policy
	for _, policy := range policies {
		if policy == nil || !policy.Enabled {
			continue
		}
		for _, rule := range policy.Rules {
			if rule == nil || !rule.Enabled {
				continue
			}
			if rule.DestinationResource.Type == PolicyResourceType && rule.DestinationResource.ID == exitNodeID {
				out = append(out, policy)
				break
			}
		}
	}
	return out
}
