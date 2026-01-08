package types

import (
	"context"

	nbdns "github.com/netbirdio/netbird/dns"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/route"
)

func (a *Account) GetPeerNetworkMapComponents(
	ctx context.Context,
	peerID string,
	peersCustomZone nbdns.CustomZone,
	validatedPeersMap map[string]struct{},
	resourcePolicies map[string][]*Policy,
	routers map[string]map[string]*routerTypes.NetworkRouter,
	groupIDToUserIDs map[string][]string,
) *NetworkMapComponents {

	peer := a.Peers[peerID]
	if peer == nil {
		return nil
	}

	if _, ok := validatedPeersMap[peerID]; !ok {
		return nil
	}

	components := &NetworkMapComponents{
		PeerID:              peerID,
		Serial:              a.Network.Serial,
		Network:             a.Network.Copy(),
		Peers:               make(map[string]*nbpeer.Peer, len(a.Peers)/4),
		Groups:              make(map[string]*Group, len(a.Groups)/4),
		Policies:            make([]*Policy, 0, len(a.Policies)/4),
		Routes:              make([]*route.Route, 0, len(a.Routes)/4),
		NameServerGroups:    make([]*nbdns.NameServerGroup, 0),
		CustomZoneDomain:    peersCustomZone.Domain,
		AllDNSRecords:       peersCustomZone.Records,
		ResourcePoliciesMap: make(map[string][]*Policy),
		RoutersMap:          make(map[string]map[string]*routerTypes.NetworkRouter),
		NetworkResources:    make([]*resourceTypes.NetworkResource, 0),
		GroupIDToUserIDs:    groupIDToUserIDs,
		AllowedUserIDs:      a.getAllowedUserIDs(),
	}

	components.AccountSettings = &AccountSettingsInfo{
		PeerLoginExpirationEnabled:      a.Settings.PeerLoginExpirationEnabled,
		PeerLoginExpiration:             a.Settings.PeerLoginExpiration,
		PeerInactivityExpirationEnabled: a.Settings.PeerInactivityExpirationEnabled,
		PeerInactivityExpiration:        a.Settings.PeerInactivityExpiration,
	}

	components.DNSSettings = &a.DNSSettings

	relevantPeers, relevantGroups, relevantPolicies, relevantRoutes := a.getPeersGroupsPoliciesRoutes(ctx, peerID, validatedPeersMap)

	_, _, networkResourcesSourcePeers := a.GetNetworkResourcesRoutesToSync(ctx, peerID, resourcePolicies, routers)
	for sourcePeerID := range networkResourcesSourcePeers {
		relevantPeers[sourcePeerID] = a.GetPeer(sourcePeerID)
	}

	// for pid := range relevantPeerIDsMap {
	// 	if p := a.Peers[pid]; p != nil {
	// 		components.Peers[pid] = p
	// 	}
	// }

	// for gid := range relevantGroupIDs {
	// 	if g := a.Groups[gid]; g != nil {
	// 		components.Groups[gid] = g
	// 	}
	// }

	components.Peers = relevantPeers
	components.Groups = relevantGroups
	components.Policies = relevantPolicies
	components.Routes = relevantRoutes

	// for _, policy := range a.Policies {
	// 	if a.isPolicyRelevantForPeer(ctx, policy, peerID, relevantGroupIDs) {
	// 		components.Policies = append(components.Policies, policy)
	// 	}
	// }

	// for _, r := range a.Routes {
	// 	if a.isRouteRelevantForPeer(ctx, r, peerID, relevantGroupIDs) {
	// 		components.Routes = append(components.Routes, r)
	// 	}
	// }

	for _, nsGroup := range a.NameServerGroups {
		if nsGroup.Enabled {
			for _, gID := range nsGroup.Groups {
				if _, found := relevantGroups[gID]; found {
					components.NameServerGroups = append(components.NameServerGroups, nsGroup.Copy())
					break
				}
			}
		}
	}

	relevantResourceIDs := make(map[string]struct{})
	relevantNetworkIDs := make(map[string]struct{})

	for _, resource := range a.NetworkResources {
		if !resource.Enabled {
			continue
		}

		policies, exists := resourcePolicies[resource.ID]
		if !exists {
			continue
		}

		isRelevant := false

		networkRoutingPeers, routerExists := routers[resource.NetworkID]
		if routerExists {
			if _, ok := networkRoutingPeers[peerID]; ok {
				isRelevant = true
			}
		}

		if !isRelevant {
			for _, policy := range policies {
				var peers []string
				if policy.Rules[0].SourceResource.Type == ResourceTypePeer && policy.Rules[0].SourceResource.ID != "" {
					peers = []string{policy.Rules[0].SourceResource.ID}
				} else {
					peers = a.getUniquePeerIDsFromGroupsIDs(ctx, policy.SourceGroups())
				}

				for _, p := range peers {
					if p == peerID && a.validatePostureChecksOnPeer(ctx, policy.SourcePostureChecks, peerID) {
						isRelevant = true
						break
					}
				}

				if isRelevant {
					break
				}
			}
		}

		if isRelevant {
			relevantResourceIDs[resource.ID] = struct{}{}
			relevantNetworkIDs[resource.NetworkID] = struct{}{}
			components.NetworkResources = append(components.NetworkResources, resource)
		}
	}

	for resID, policies := range resourcePolicies {
		if _, isRelevant := relevantResourceIDs[resID]; !isRelevant {
			continue
		}

		for _, p := range policies {
			for _, rule := range p.Rules {
				for _, srcGroupID := range rule.Sources {
					if g := a.Groups[srcGroupID]; g != nil {
						if _, exists := components.Groups[srcGroupID]; !exists {
							components.Groups[srcGroupID] = g
						}
					}
				}
				for _, dstGroupID := range rule.Destinations {
					if g := a.Groups[dstGroupID]; g != nil {
						if _, exists := components.Groups[dstGroupID]; !exists {
							components.Groups[dstGroupID] = g
						}
					}
				}
			}
		}
		components.ResourcePoliciesMap[resID] = policies
	}

	for networkID, networkRouters := range routers {
		if _, isRelevant := relevantNetworkIDs[networkID]; !isRelevant {
			continue
		}

		components.RoutersMap[networkID] = networkRouters
		for peerIDKey := range networkRouters {
			if _, exists := components.Peers[peerIDKey]; !exists {
				if p := a.Peers[peerIDKey]; p != nil {
					components.Peers[peerIDKey] = p
				}
			}
		}
	}

	for groupID, groupInfo := range components.Groups {
		needsFiltering := false
		for _, pid := range groupInfo.Peers {
			if _, exists := components.Peers[pid]; !exists {
				needsFiltering = true
				break
			}
		}

		if !needsFiltering {
			continue
		}

		filteredPeers := make([]string, 0, len(groupInfo.Peers))
		for _, pid := range groupInfo.Peers {
			if _, exists := components.Peers[pid]; exists {
				filteredPeers = append(filteredPeers, pid)
			}
		}

		if len(filteredPeers) == 0 {
			delete(components.Groups, groupID)
		} else {
			groupInfo.Peers = filteredPeers
			components.Groups[groupID] = groupInfo
		}
	}

	return components
}

func (a *Account) getPeersGroupsPoliciesRoutes(
	ctx context.Context,
	peerID string,
	validatedPeersMap map[string]struct{},
) (map[string]*nbpeer.Peer, map[string]*Group, []*Policy, []*route.Route) {
	relevantPeerIDs := make(map[string]*nbpeer.Peer, len(a.Peers)/4)
	relevantGroupIDs := make(map[string]*Group, len(a.Groups)/4)
	relevantPolicies := make([]*Policy, 0, len(a.Policies))
	relevantRoutes := make([]*route.Route, 0, len(a.Routes))

	relevantPeerIDs[peerID] = a.GetPeer(peerID)

	for groupID, group := range a.Groups {
		for _, pid := range group.Peers {
			if pid == peerID {
				relevantGroupIDs[groupID] = a.GetGroup(groupID)
				break
			}
		}
	}

	for _, policy := range a.Policies {
		if !policy.Enabled {
			continue
		}

		policyRelevant := false
		for _, rule := range policy.Rules {
			if !rule.Enabled {
				continue
			}

			var sourcePeers, destinationPeers []string
			var peerInSources, peerInDestinations bool

			if rule.SourceResource.Type == ResourceTypePeer && rule.SourceResource.ID != "" {
				sourcePeers = []string{rule.SourceResource.ID}
				if rule.SourceResource.ID == peerID {
					peerInSources = true
				}
			} else {
				sourcePeers, peerInSources = a.getPeersFromGroups(ctx, rule.Sources, peerID, policy.SourcePostureChecks, validatedPeersMap)
			}

			if rule.DestinationResource.Type == ResourceTypePeer && rule.DestinationResource.ID != "" {
				destinationPeers = []string{rule.DestinationResource.ID}
				if rule.DestinationResource.ID == peerID {
					peerInDestinations = true
				}
			} else {
				destinationPeers, peerInDestinations = a.getPeersFromGroups(ctx, rule.Destinations, peerID, nil, validatedPeersMap)
			}

			if peerInSources {
				policyRelevant = true
				for _, pid := range destinationPeers {
					relevantPeerIDs[pid] = a.GetPeer(pid)
				}
				for _, dstGroupID := range rule.Destinations {
					relevantGroupIDs[dstGroupID] = a.GetGroup(dstGroupID)
				}
			}

			if peerInDestinations {
				policyRelevant = true
				for _, pid := range sourcePeers {
					relevantPeerIDs[pid] = a.GetPeer(pid)
				}
				for _, srcGroupID := range rule.Sources {
					relevantGroupIDs[srcGroupID] = a.GetGroup(srcGroupID)
				}
			}
		}
		if policyRelevant {
			relevantPolicies = append(relevantPolicies, policy)
		}
	}

	for _, r := range a.Routes {
		isRelevant := false

		for _, groupID := range r.Groups {
			if _, found := relevantGroupIDs[groupID]; found {
				isRelevant = true
				break
			}
		}

		if r.Peer == peerID || r.PeerID == peerID {
			isRelevant = true
		}

		for _, groupID := range r.PeerGroups {
			if group := a.Groups[groupID]; group != nil {
				for _, pid := range group.Peers {
					if pid == peerID {
						isRelevant = true
						break
					}
				}
			}
		}

		if isRelevant {
			for _, groupID := range r.Groups {
				relevantGroupIDs[groupID] = a.GetGroup(groupID)
			}
			for _, groupID := range r.PeerGroups {
				relevantGroupIDs[groupID] = a.GetGroup(groupID)
			}
			for _, groupID := range r.AccessControlGroups {
				relevantGroupIDs[groupID] = a.GetGroup(groupID)
			}

			if r.Peer != "" {
				relevantPeerIDs[r.Peer] = a.GetPeer(r.Peer)
			}
			if r.PeerID != "" {
				relevantPeerIDs[r.PeerID] = a.GetPeer(r.PeerID)
			}

			relevantRoutes = append(relevantRoutes, r)
		}
	}

	return relevantPeerIDs, relevantGroupIDs, relevantPolicies, relevantRoutes
}

func (a *Account) getPeersFromGroups(ctx context.Context, groups []string, peerID string, sourcePostureChecksIDs []string, validatedPeersMap map[string]struct{}) ([]string, bool) {
	peerInGroups := false
	uniquePeerIDs := a.getUniquePeerIDsFromGroupsIDs(ctx, groups)
	filteredPeerIDs := make([]string, 0, len(uniquePeerIDs))

	for _, p := range uniquePeerIDs {
		peer, ok := a.Peers[p]
		if !ok || peer == nil {
			continue
		}

		isValid := a.validatePostureChecksOnPeer(ctx, sourcePostureChecksIDs, peer.ID)
		if !isValid {
			continue
		}

		if _, ok := validatedPeersMap[peer.ID]; !ok {
			continue
		}

		if peer.ID == peerID {
			peerInGroups = true
			continue
		}

		filteredPeerIDs = append(filteredPeerIDs, peer.ID)
	}

	return filteredPeerIDs, peerInGroups
}

func (a *Account) isPolicyRelevantForPeer(ctx context.Context, policy *Policy, peerID string, relevantGroupIDs map[string]struct{}) bool {
	for _, rule := range policy.Rules {
		for _, srcGroupID := range rule.Sources {
			if _, found := relevantGroupIDs[srcGroupID]; found {
				return true
			}
		}

		for _, dstGroupID := range rule.Destinations {
			if _, found := relevantGroupIDs[dstGroupID]; found {
				return true
			}
		}

		if rule.SourceResource.Type == ResourceTypePeer && rule.SourceResource.ID == peerID {
			return true
		}

		if rule.DestinationResource.Type == ResourceTypePeer && rule.DestinationResource.ID == peerID {
			return true
		}
	}

	return false
}

func (a *Account) isRouteRelevantForPeer(ctx context.Context, r *route.Route, peerID string, relevantGroupIDs map[string]struct{}) bool {
	if r.Peer == peerID || r.PeerID == peerID {
		return true
	}

	for _, groupID := range r.Groups {
		if _, found := relevantGroupIDs[groupID]; found {
			return true
		}
	}

	for _, groupID := range r.PeerGroups {
		if group := a.Groups[groupID]; group != nil {
			for _, pid := range group.Peers {
				if pid == peerID {
					return true
				}
			}
		}
	}

	for _, groupID := range r.AccessControlGroups {
		if _, found := relevantGroupIDs[groupID]; found {
			return true
		}
	}

	return false
}
