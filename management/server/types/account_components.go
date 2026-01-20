package types

import (
	"context"
	"slices"

	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/internals/modules/zones"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/route"
)

func (a *Account) GetPeerNetworkMapComponents(
	ctx context.Context,
	peerID string,
	peersCustomZone nbdns.CustomZone,
	accountZones []*zones.Zone,
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
		NameServerGroups:    make([]*nbdns.NameServerGroup, 0),
		CustomZoneDomain:    peersCustomZone.Domain,
		ResourcePoliciesMap: make(map[string][]*Policy),
		RoutersMap:          make(map[string]map[string]*routerTypes.NetworkRouter),
		NetworkResources:    make([]*resourceTypes.NetworkResource, 0),
		GroupIDToUserIDs:    groupIDToUserIDs,
		AllowedUserIDs:      a.getAllowedUserIDs(),
		PostureFailedPeers:  make(map[string]map[string]struct{}, len(a.Policies)),
	}

	components.AccountSettings = &AccountSettingsInfo{
		PeerLoginExpirationEnabled:      a.Settings.PeerLoginExpirationEnabled,
		PeerLoginExpiration:             a.Settings.PeerLoginExpiration,
		PeerInactivityExpirationEnabled: a.Settings.PeerInactivityExpirationEnabled,
		PeerInactivityExpiration:        a.Settings.PeerInactivityExpiration,
	}

	components.DNSSettings = &a.DNSSettings

	relevantPeers, relevantGroups, relevantPolicies, relevantRoutes := a.getPeersGroupsPoliciesRoutes(ctx, peerID, validatedPeersMap, &components.PostureFailedPeers)

	components.Peers = relevantPeers
	components.Groups = relevantGroups
	components.Policies = relevantPolicies
	components.Routes = relevantRoutes
	components.AllDNSRecords = filterDNSRecordsByPeers(peersCustomZone.Records, relevantPeers)

	peerGroups := a.GetPeerGroups(peerID)
	components.AccountZones = filterPeerAppliedZones(ctx, accountZones, peerGroups)

	for _, nsGroup := range a.NameServerGroups {
		if nsGroup.Enabled {
			for _, gID := range nsGroup.Groups {
				if _, found := relevantGroups[gID]; found {
					components.NameServerGroups = append(components.NameServerGroups, nsGroup)
					break
				}
			}
		}
	}

	for _, resource := range a.NetworkResources {
		if !resource.Enabled {
			continue
		}

		policies, exists := resourcePolicies[resource.ID]
		if !exists {
			continue
		}

		addSourcePeers := false

		networkRoutingPeers, routerExists := routers[resource.NetworkID]
		if routerExists {
			if _, ok := networkRoutingPeers[peerID]; ok {
				addSourcePeers = true
			}
		}

		for _, policy := range policies {
			if addSourcePeers {
				var peers []string
				if policy.Rules[0].SourceResource.Type == ResourceTypePeer && policy.Rules[0].SourceResource.ID != "" {
					peers = []string{policy.Rules[0].SourceResource.ID}
				} else {
					peers = a.getUniquePeerIDsFromGroupsIDs(ctx, policy.SourceGroups())
				}
				for _, pID := range a.getPostureValidPeersSaveFailed(peers, policy.SourcePostureChecks, &components.PostureFailedPeers) {
					if _, exists := components.Peers[pID]; !exists {
						components.Peers[pID] = a.GetPeer(pID)
					}
				}
			} else {
				peerInSources := false
				if policy.Rules[0].SourceResource.Type == ResourceTypePeer && policy.Rules[0].SourceResource.ID != "" {
					peerInSources = policy.Rules[0].SourceResource.ID == peerID
				} else {
					for _, groupID := range policy.SourceGroups() {
						if group := a.GetGroup(groupID); group != nil && slices.Contains(group.Peers, peerID) {
							peerInSources = true
							break
						}
					}
				}
				if !peerInSources {
					continue
				}
				isValid, pname := a.validatePostureChecksOnPeerGetFailed(ctx, policy.SourcePostureChecks, peerID)
				if !isValid && len(pname) > 0 {
					if _, ok := (*components).PostureFailedPeers[pname]; !ok {
						(*components).PostureFailedPeers[pname] = make(map[string]struct{})
					}
					(*components).PostureFailedPeers[pname][peer.ID] = struct{}{}
					continue
				}
				addSourcePeers = true
			}

			for _, rule := range policy.Rules {
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
			components.ResourcePoliciesMap[resource.ID] = policies
		}

		components.RoutersMap[resource.NetworkID] = networkRoutingPeers
		for peerIDKey := range networkRoutingPeers {
			if _, exists := components.Peers[peerIDKey]; !exists {
				if p := a.Peers[peerIDKey]; p != nil {
					components.Peers[peerIDKey] = p
				}
			}
		}

		if addSourcePeers {
			components.NetworkResources = append(components.NetworkResources, resource)
		}
	}

	filterGroupPeers(&components.Groups, components.Peers)

	return components
}

func (a *Account) getPeersGroupsPoliciesRoutes(
	ctx context.Context,
	peerID string,
	validatedPeersMap map[string]struct{},
	postureFailedPeers *map[string]map[string]struct{},
) (map[string]*nbpeer.Peer, map[string]*Group, []*Policy, []*route.Route) {
	relevantPeerIDs := make(map[string]*nbpeer.Peer, len(a.Peers)/4)
	relevantGroupIDs := make(map[string]*Group, len(a.Groups)/4)
	relevantPolicies := make([]*Policy, 0, len(a.Policies))
	relevantRoutes := make([]*route.Route, 0, len(a.Routes))

	relevantPeerIDs[peerID] = a.GetPeer(peerID)

	for groupID, group := range a.Groups {
		if slices.Contains(group.Peers, peerID) {
			relevantGroupIDs[groupID] = a.GetGroup(groupID)
		}
	}

	routeAccessControlGroups := make(map[string]struct{})
	for _, r := range a.Routes {
		for _, groupID := range r.Groups {
			relevantGroupIDs[groupID] = a.GetGroup(groupID)
		}
		for _, groupID := range r.PeerGroups {
			relevantGroupIDs[groupID] = a.GetGroup(groupID)
		}
		if r.Enabled {
			for _, groupID := range r.AccessControlGroups {
				relevantGroupIDs[groupID] = a.GetGroup(groupID)
				routeAccessControlGroups[groupID] = struct{}{}
			}
		}
		relevantRoutes = append(relevantRoutes, r)
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

			if len(routeAccessControlGroups) > 0 {
				for _, destGroupID := range rule.Destinations {
					if _, needed := routeAccessControlGroups[destGroupID]; needed {
						policyRelevant = true
						for _, srcGroupID := range rule.Sources {
							relevantGroupIDs[srcGroupID] = a.GetGroup(srcGroupID)
						}
						for _, dstGroupID := range rule.Destinations {
							relevantGroupIDs[dstGroupID] = a.GetGroup(dstGroupID)
						}
						break
					}
				}
			}

			var sourcePeers, destinationPeers []string
			var peerInSources, peerInDestinations bool

			if rule.SourceResource.Type == ResourceTypePeer && rule.SourceResource.ID != "" {
				sourcePeers = []string{rule.SourceResource.ID}
				if rule.SourceResource.ID == peerID {
					peerInSources = true
				}
			} else {
				sourcePeers, peerInSources = a.getPeersFromGroups(ctx, rule.Sources, peerID, policy.SourcePostureChecks, validatedPeersMap, postureFailedPeers)
			}

			if rule.DestinationResource.Type == ResourceTypePeer && rule.DestinationResource.ID != "" {
				destinationPeers = []string{rule.DestinationResource.ID}
				if rule.DestinationResource.ID == peerID {
					peerInDestinations = true
				}
			} else {
				destinationPeers, peerInDestinations = a.getPeersFromGroups(ctx, rule.Destinations, peerID, nil, validatedPeersMap, postureFailedPeers)
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

	return relevantPeerIDs, relevantGroupIDs, relevantPolicies, relevantRoutes
}

func (a *Account) getPeersFromGroups(ctx context.Context, groups []string, peerID string, sourcePostureChecksIDs []string,
	validatedPeersMap map[string]struct{}, postureFailedPeers *map[string]map[string]struct{}) ([]string, bool) {
	peerInGroups := false
	filteredPeerIDs := make([]string, 0, len(a.Peers))
	seenPeerIds := make(map[string]struct{}, len(groups))

	for _, gid := range groups {
		group := a.GetGroup(gid)
		if group == nil {
			continue
		}

		if group.IsGroupAll() || len(groups) == 1 {
			filteredPeerIDs = filteredPeerIDs[:0]
			seenPeerIds = make(map[string]struct{}, len(group.Peers))
			peerInGroups = false
			for _, pid := range group.Peers {
				peer, ok := a.Peers[pid]
				if !ok || peer == nil {
					continue
				}

				isValid, pname := a.validatePostureChecksOnPeerGetFailed(ctx, sourcePostureChecksIDs, peer.ID)
				if !isValid && len(pname) > 0 {
					if _, ok := (*postureFailedPeers)[pname]; !ok {
						(*postureFailedPeers)[pname] = make(map[string]struct{})
					}
					(*postureFailedPeers)[pname][peer.ID] = struct{}{}
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

		for _, pid := range group.Peers {
			if _, seen := seenPeerIds[pid]; seen {
				continue
			}
			seenPeerIds[pid] = struct{}{}
			peer, ok := a.Peers[pid]
			if !ok || peer == nil {
				continue
			}

			isValid, pname := a.validatePostureChecksOnPeerGetFailed(ctx, sourcePostureChecksIDs, peer.ID)
			if !isValid && len(pname) > 0 {
				if _, ok := (*postureFailedPeers)[pname]; !ok {
					(*postureFailedPeers)[pname] = make(map[string]struct{})
				}
				(*postureFailedPeers)[pname][peer.ID] = struct{}{}
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
	}

	return filteredPeerIDs, peerInGroups
}

func (a *Account) validatePostureChecksOnPeerGetFailed(ctx context.Context, sourcePostureChecksID []string, peerID string) (bool, string) {
	peer, ok := a.Peers[peerID]
	if !ok && peer == nil {
		return false, ""
	}

	for _, postureChecksID := range sourcePostureChecksID {
		postureChecks := a.GetPostureChecks(postureChecksID)
		if postureChecks == nil {
			continue
		}

		for _, check := range postureChecks.GetChecks() {
			isValid, _ := check.Check(ctx, *peer)
			if !isValid {
				return false, postureChecksID
			}
		}
	}
	return true, ""
}

func (a *Account) getPostureValidPeersSaveFailed(inputPeers []string, postureChecksIDs []string, postureFailedPeers *map[string]map[string]struct{}) []string {
	var dest []string
	for _, peerID := range inputPeers {
		valid, pname := a.validatePostureChecksOnPeerGetFailed(context.Background(), postureChecksIDs, peerID)
		if valid {
			dest = append(dest, peerID)
			continue
		}
		if _, ok := (*postureFailedPeers)[pname]; !ok {
			(*postureFailedPeers)[pname] = make(map[string]struct{})
		}
		(*postureFailedPeers)[pname][peerID] = struct{}{}
	}
	return dest
}

func filterGroupPeers(groups *map[string]*Group, peers map[string]*nbpeer.Peer) {
	for groupID, groupInfo := range *groups {
		filteredPeers := make([]string, 0, len(groupInfo.Peers))
		for _, pid := range groupInfo.Peers {
			if _, exists := peers[pid]; exists {
				filteredPeers = append(filteredPeers, pid)
			}
		}

		if len(filteredPeers) == 0 {
			delete(*groups, groupID)
		} else if len(filteredPeers) != len(groupInfo.Peers) {
			ng := groupInfo.Copy()
			ng.Peers = filteredPeers
			(*groups)[groupID] = ng
		}
	}
}

func filterDNSRecordsByPeers(records []nbdns.SimpleRecord, peers map[string]*nbpeer.Peer) []nbdns.SimpleRecord {
	if len(records) == 0 || len(peers) == 0 {
		return nil
	}

	peerIPs := make(map[string]struct{}, len(peers))
	for _, peer := range peers {
		if peer != nil {
			peerIPs[peer.IP.String()] = struct{}{}
		}
	}

	filteredRecords := make([]nbdns.SimpleRecord, 0, len(records))
	for _, record := range records {
		if _, exists := peerIPs[record.RData]; exists {
			filteredRecords = append(filteredRecords, record)
		}
	}

	return filteredRecords
}
