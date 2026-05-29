package types

import (
	nbdns "github.com/netbirdio/netbird/dns"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/route"
)

type GroupCompact struct {
	Name        string
	PeerIndexes []int
}

type NetworkMapComponentsCompact struct {
	PeerID string

	Network          *Network
	AccountSettings  *AccountSettingsInfo
	DNSSettings      *DNSSettings
	CustomZoneDomain string

	AllPeers          []*nbpeer.Peer
	PeerIndexes       []int
	RouterPeerIndexes []int

	Groups              map[string]*GroupCompact
	AllPolicies         []*Policy
	PolicyIndexes       []int
	ResourcePoliciesMap map[string][]int
	Routes              []*route.Route
	NameServerGroups    []*nbdns.NameServerGroup
	AllDNSRecords       []nbdns.SimpleRecord
	AccountZones        []nbdns.CustomZone

	RoutersMap       map[string]map[string]*routerTypes.NetworkRouter
	NetworkResources []*resourceTypes.NetworkResource

	GroupIDToUserIDs   map[string][]string
	AllowedUserIDs     map[string]struct{}
	PostureFailedPeers map[string]map[string]struct{}
}

func (c *NetworkMapComponents) ToCompact() *NetworkMapComponentsCompact {
	peerToIndex := make(map[string]int)
	var allPeers []*nbpeer.Peer

	for id, peer := range c.Peers {
		if _, exists := peerToIndex[id]; !exists {
			peerToIndex[id] = len(allPeers)
			allPeers = append(allPeers, peer)
		}
	}

	for id, peer := range c.RouterPeers {
		if _, exists := peerToIndex[id]; !exists {
			peerToIndex[id] = len(allPeers)
			allPeers = append(allPeers, peer)
		}
	}

	peerIndexes := make([]int, 0, len(c.Peers))
	for id := range c.Peers {
		peerIndexes = append(peerIndexes, peerToIndex[id])
	}

	routerPeerIndexes := make([]int, 0, len(c.RouterPeers))
	for id := range c.RouterPeers {
		routerPeerIndexes = append(routerPeerIndexes, peerToIndex[id])
	}

	groups := make(map[string]*GroupCompact, len(c.Groups))
	for id, group := range c.Groups {
		peerIdxs := make([]int, 0, len(group.Peers))
		for _, peerID := range group.Peers {
			if idx, ok := peerToIndex[peerID]; ok {
				peerIdxs = append(peerIdxs, idx)
			}
		}
		groups[id] = &GroupCompact{
			Name:        group.Name,
			PeerIndexes: peerIdxs,
		}
	}

	policyToIndex := make(map[*Policy]int)
	var allPolicies []*Policy

	for _, policy := range c.Policies {
		if _, exists := policyToIndex[policy]; !exists {
			policyToIndex[policy] = len(allPolicies)
			allPolicies = append(allPolicies, policy)
		}
	}

	for _, policies := range c.ResourcePoliciesMap {
		for _, policy := range policies {
			if _, exists := policyToIndex[policy]; !exists {
				policyToIndex[policy] = len(allPolicies)
				allPolicies = append(allPolicies, policy)
			}
		}
	}

	policyIndexes := make([]int, len(c.Policies))
	for i, policy := range c.Policies {
		policyIndexes[i] = policyToIndex[policy]
	}

	var resourcePoliciesMap map[string][]int
	if len(c.ResourcePoliciesMap) > 0 {
		resourcePoliciesMap = make(map[string][]int, len(c.ResourcePoliciesMap))
		for resID, policies := range c.ResourcePoliciesMap {
			indexes := make([]int, len(policies))
			for i, policy := range policies {
				indexes[i] = policyToIndex[policy]
			}
			resourcePoliciesMap[resID] = indexes
		}
	}

	return &NetworkMapComponentsCompact{
		PeerID:           c.PeerID,
		Network:          c.Network,
		AccountSettings:  c.AccountSettings,
		DNSSettings:      c.DNSSettings,
		CustomZoneDomain: c.CustomZoneDomain,

		AllPeers:          allPeers,
		PeerIndexes:       peerIndexes,
		RouterPeerIndexes: routerPeerIndexes,

		Groups:              groups,
		AllPolicies:         allPolicies,
		PolicyIndexes:       policyIndexes,
		ResourcePoliciesMap: resourcePoliciesMap,
		Routes:              c.Routes,
		NameServerGroups:    c.NameServerGroups,
		AllDNSRecords:       c.AllDNSRecords,
		AccountZones:        c.AccountZones,

		RoutersMap:       c.RoutersMap,
		NetworkResources: c.NetworkResources,

		GroupIDToUserIDs:   c.GroupIDToUserIDs,
		AllowedUserIDs:     c.AllowedUserIDs,
		PostureFailedPeers: c.PostureFailedPeers,
	}
}

func (c *NetworkMapComponentsCompact) ToFull() *NetworkMapComponents {
	peers := make(map[string]*nbpeer.Peer, len(c.PeerIndexes))
	for _, idx := range c.PeerIndexes {
		if idx >= 0 && idx < len(c.AllPeers) {
			peer := c.AllPeers[idx]
			peers[peer.ID] = peer
		}
	}

	routerPeers := make(map[string]*nbpeer.Peer, len(c.RouterPeerIndexes))
	for _, idx := range c.RouterPeerIndexes {
		if idx >= 0 && idx < len(c.AllPeers) {
			peer := c.AllPeers[idx]
			routerPeers[peer.ID] = peer
		}
	}

	groups := make(map[string]*Group, len(c.Groups))
	for id, gc := range c.Groups {
		peerIDs := make([]string, 0, len(gc.PeerIndexes))
		for _, idx := range gc.PeerIndexes {
			if idx >= 0 && idx < len(c.AllPeers) {
				peerIDs = append(peerIDs, c.AllPeers[idx].ID)
			}
		}
		groups[id] = &Group{
			ID:    id,
			Name:  gc.Name,
			Peers: peerIDs,
		}
	}

	policies := make([]*Policy, len(c.PolicyIndexes))
	for i, idx := range c.PolicyIndexes {
		if idx >= 0 && idx < len(c.AllPolicies) {
			policies[i] = c.AllPolicies[idx]
		}
	}

	var resourcePoliciesMap map[string][]*Policy
	if len(c.ResourcePoliciesMap) > 0 {
		resourcePoliciesMap = make(map[string][]*Policy, len(c.ResourcePoliciesMap))
		for resID, indexes := range c.ResourcePoliciesMap {
			pols := make([]*Policy, 0, len(indexes))
			for _, idx := range indexes {
				if idx >= 0 && idx < len(c.AllPolicies) {
					pols = append(pols, c.AllPolicies[idx])
				}
			}
			resourcePoliciesMap[resID] = pols
		}
	}

	return &NetworkMapComponents{
		PeerID:           c.PeerID,
		Network:          c.Network,
		AccountSettings:  c.AccountSettings,
		DNSSettings:      c.DNSSettings,
		CustomZoneDomain: c.CustomZoneDomain,

		Peers:       peers,
		RouterPeers: routerPeers,

		Groups:           groups,
		Policies:         policies,
		Routes:           c.Routes,
		NameServerGroups: c.NameServerGroups,
		AllDNSRecords:    c.AllDNSRecords,
		AccountZones:     c.AccountZones,

		ResourcePoliciesMap: resourcePoliciesMap,
		RoutersMap:          c.RoutersMap,
		NetworkResources:    c.NetworkResources,

		GroupIDToUserIDs:   c.GroupIDToUserIDs,
		AllowedUserIDs:     c.AllowedUserIDs,
		PostureFailedPeers: c.PostureFailedPeers,
	}
}
