package networkmap

import (
	"slices"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/types"
)

// componentsIndex maps groups and peers to the policies, routes and network
// resources that reference them, so a peer's components are assembled from
// what it can reach instead of a scan over the whole account. Every lookup
// yields a superset of the relevant items; the calculation decides on each.
type componentsIndex struct {
	policiesByGroup    map[string][]int
	policiesByPeer     map[string][]int
	routesByGroup      map[string][]int
	routesByPeer       map[string][]int
	resourcesByGroup   map[string][]int
	resourcesByPeer    map[string][]int
	resourcesByNetwork map[string][]int
	networksByRouter   map[string][]string
}

// componentsIndex returns the index, built once after the proxy policies are
// injected, since those are part of what it indexes.
func (nmd *NetworkMapData) componentsIndex() *componentsIndex {
	nmd.indexOnce.Do(func() {
		nmd.InjectProxyPolicies()
		nmd.index = nmd.buildComponentsIndex()
	})
	return nmd.index
}

func (nmd *NetworkMapData) buildComponentsIndex() *componentsIndex {
	idx := &componentsIndex{
		policiesByGroup:    make(map[string][]int),
		policiesByPeer:     make(map[string][]int),
		routesByGroup:      make(map[string][]int),
		routesByPeer:       make(map[string][]int),
		resourcesByGroup:   make(map[string][]int),
		resourcesByPeer:    make(map[string][]int),
		resourcesByNetwork: make(map[string][]int),
		networksByRouter:   make(map[string][]string),
	}

	for i, policy := range nmd.Policies {
		if policy == nil || !policy.Enabled {
			continue
		}
		for _, rule := range policy.Rules {
			if rule == nil || !rule.Enabled {
				continue
			}
			addIndexed(idx.policiesByGroup, i, rule.Sources...)
			addIndexed(idx.policiesByGroup, i, rule.Destinations...)
			if isPeerResource(rule.SourceResource) {
				addIndexed(idx.policiesByPeer, i, rule.SourceResource.ID)
			}
			if isPeerResource(rule.DestinationResource) {
				addIndexed(idx.policiesByPeer, i, rule.DestinationResource.ID)
			}
		}
	}

	for i, r := range nmd.Routes {
		if r == nil {
			continue
		}
		if r.Peer != "" {
			addIndexed(idx.routesByPeer, i, r.Peer)
		}
		addIndexed(idx.routesByGroup, i, r.PeerGroups...)
		addIndexed(idx.routesByGroup, i, r.Groups...)
	}

	for i, resource := range nmd.NetworkResources {
		if resource == nil || !resource.Enabled {
			continue
		}
		addIndexed(idx.resourcesByNetwork, i, resource.NetworkID)
		for _, policy := range nmd.ResourcePolicies[resource.ID] {
			if policy == nil || !policy.Enabled || len(policy.Rules) == 0 || policy.Rules[0] == nil {
				continue
			}
			if isPeerResource(policy.Rules[0].SourceResource) {
				addIndexed(idx.resourcesByPeer, i, policy.Rules[0].SourceResource.ID)
				continue
			}
			addIndexed(idx.resourcesByGroup, i, policy.SourceGroups()...)
		}
	}

	for networkID, routers := range nmd.Routers {
		for peerID := range routers {
			idx.networksByRouter[peerID] = append(idx.networksByRouter[peerID], networkID)
		}
	}

	return idx
}

// addIndexed appends item under every key, skipping a key whose last item it
// already is, so items stay unique per key while they are added in order.
func addIndexed(index map[string][]int, item int, keys ...string) {
	for _, key := range keys {
		items := index[key]
		if n := len(items); n > 0 && items[n-1] == item {
			continue
		}
		index[key] = append(items, item)
	}
}

// lookup returns the items indexed under the peer and under any of its
// groups, sorted and deduplicated so they keep the account's order.
func lookup(byPeer, byGroup map[string][]int, peerID string, groups map[string]struct{}) []int {
	items := slices.Clone(byPeer[peerID])
	for groupID := range groups {
		items = append(items, byGroup[groupID]...)
	}
	return sortedUnique(items)
}

func sortedUnique(items []int) []int {
	slices.Sort(items)
	return slices.Compact(items)
}

func isPeerResource(resource nmdata.Resource) bool {
	return resource.Type == string(types.ResourceTypePeer) && resource.ID != ""
}

func anyInSet(ids []string, set map[string]struct{}) bool {
	for _, id := range ids {
		if _, ok := set[id]; ok {
			return true
		}
	}
	return false
}
