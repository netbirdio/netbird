package networkmap

import (
	"slices"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/types"
)

type sshRequirements struct {
	neededGroupIDs     map[string]struct{}
	needAllowedUserIDs bool
}

// GetPeerNetworkMapComponents computes the peer's NetworkMapComponents from the
// slim twin store. It mirrors the former Account.GetPeerNetworkMapComponents
// exactly, operating on nmdata twins throughout — no Account reference and no
// twin↔real conversion, since the produced components hold twins.
func (nmd *NetworkMapData) GetPeerNetworkMapComponents(peerID string, peersCustomZone nmdata.CustomZone) *types.NetworkMapComponents {
	peer := nmd.Peers[peerID]
	if peer == nil {
		return types.EmptyNetworkMapComponents(&types.NetworkMapComponents{
			PeerID:  peerID,
			Network: nmd.Network,
			Peers:   map[string]*nmdata.Peer{peerID: peer},
		})
	}

	if _, ok := nmd.ValidatedPeers[peerID]; !ok {
		return types.EmptyNetworkMapComponents(&types.NetworkMapComponents{
			PeerID:  peerID,
			Network: nmd.Network,
			Peers:   map[string]*nmdata.Peer{peerID: peer},
		})
	}

	components := &types.NetworkMapComponents{
		PeerID:                    peerID,
		Network:                   nmd.Network,
		AccountSettings:           nmd.AccountSettings,
		DNSSettings:               nmd.DNSSettings,
		CustomZoneDomain:          peersCustomZone.Domain,
		NameServerGroups:          make([]*nmdata.NameServerGroup, 0),
		ResourcePoliciesMap:       make(map[string][]*nmdata.Policy),
		RoutersMap:                make(map[string]map[string]*nmdata.NetworkRouter),
		NetworkResources:          make([]*nmdata.NetworkResource, 0),
		PostureFailedPeers:        make(map[string]map[string]struct{}, len(nmd.PostureChecks)),
		RouterPeers:               make(map[string]*nmdata.Peer),
		NetworkXIDToPublicID:      nmd.NetworkXIDToPublicID,
		PostureCheckXIDToPublicID: nmd.PostureCheckXIDToPublicID,
	}

	relevantPeers, relevantGroups, relevantPolicies, relevantRoutes, sshReqs := nmd.getPeersGroupsPoliciesRoutes(peerID, peer.SSHEnabled, &components.PostureFailedPeers)

	if len(sshReqs.neededGroupIDs) > 0 {
		components.GroupIDToUserIDs = filterGroupIDToUserIDs(nmd.GroupIDToUserIDs, sshReqs.neededGroupIDs)
	}
	if sshReqs.needAllowedUserIDs {
		components.AllowedUserIDs = nmd.getAllowedUserIDs()
	}

	components.Peers = relevantPeers
	components.Groups = relevantGroups
	components.Policies = relevantPolicies
	components.Routes = relevantRoutes
	components.AllDNSRecords = filterDNSRecordsByPeers(peersCustomZone.Records, relevantPeers, peer.SupportsIPv6() && peer.IPv6.IsValid())

	peerGroups := nmd.GetPeerGroups(peerID)
	components.AccountZones = nmd.appliedZones(peerGroups)
	components.AccountZones = append(components.AccountZones, nmd.privateServiceZones(peerGroups)...)

	for _, nsGroup := range nmd.NameServerGroups {
		if nsGroup.Enabled {
			for _, gID := range nsGroup.Groups {
				if _, found := relevantGroups[gID]; found {
					components.NameServerGroups = append(components.NameServerGroups, nsGroup)
					break
				}
			}
		}
	}

	for _, resource := range nmd.NetworkResources {
		if !resource.Enabled {
			continue
		}

		policies, exists := nmd.ResourcePolicies[resource.ID]
		if !exists {
			continue
		}

		addSourcePeers := false

		networkRoutingPeers, routerExists := nmd.Routers[resource.NetworkID]
		if routerExists {
			if _, ok := networkRoutingPeers[peerID]; ok {
				addSourcePeers = true
			}
		}

		for _, policy := range policies {
			if addSourcePeers {
				var peers []string
				if policy.Rules[0].SourceResource.Type == string(types.ResourceTypePeer) && policy.Rules[0].SourceResource.ID != "" {
					peers = []string{policy.Rules[0].SourceResource.ID}
				} else {
					peers = nmd.getUniquePeerIDsFromGroupsIDs(policy.SourceGroups())
				}
				for _, pID := range nmd.getPostureValidPeersSaveFailed(peers, policy.SourcePostureChecks, &components.PostureFailedPeers) {
					if _, exists := components.Peers[pID]; !exists {
						components.Peers[pID] = nmd.Peers[pID]
					}
				}
			} else {
				peerInSources := false
				if policy.Rules[0].SourceResource.Type == string(types.ResourceTypePeer) && policy.Rules[0].SourceResource.ID != "" {
					peerInSources = policy.Rules[0].SourceResource.ID == peerID
				} else {
					for _, groupID := range policy.SourceGroups() {
						if group := nmd.Groups[groupID]; group != nil && slices.Contains(group.Peers, peerID) {
							peerInSources = true
							break
						}
					}
				}
				if !peerInSources {
					continue
				}
				isValid, pname := nmd.validatePostureChecksOnPeerGetFailed(policy.SourcePostureChecks, peerID)
				if !isValid && len(pname) > 0 {
					if _, ok := components.PostureFailedPeers[pname]; !ok {
						components.PostureFailedPeers[pname] = make(map[string]struct{})
					}
					components.PostureFailedPeers[pname][peer.ID] = struct{}{}
					continue
				}
				addSourcePeers = true
			}

			for _, rule := range policy.Rules {
				for _, srcGroupID := range rule.Sources {
					if g := nmd.Groups[srcGroupID]; g != nil {
						if _, exists := components.Groups[srcGroupID]; !exists {
							components.Groups[srcGroupID] = g
						}
					}
				}
				for _, dstGroupID := range rule.Destinations {
					if g := nmd.Groups[dstGroupID]; g != nil {
						if _, exists := components.Groups[dstGroupID]; !exists {
							components.Groups[dstGroupID] = g
						}
					}
				}
			}
			components.ResourcePoliciesMap[resource.ID] = policies
		}

		if addSourcePeers {
			components.RoutersMap[resource.NetworkID] = networkRoutingPeers
			for peerIDKey := range networkRoutingPeers {
				if p := nmd.Peers[peerIDKey]; p != nil {
					if _, exists := components.RouterPeers[peerIDKey]; !exists {
						components.RouterPeers[peerIDKey] = p
					}
					if _, exists := components.Peers[peerIDKey]; !exists {
						if _, validated := nmd.ValidatedPeers[peerIDKey]; validated {
							components.Peers[peerIDKey] = p
						}
					}
				}
			}
			components.NetworkResources = append(components.NetworkResources, resource)
		}
	}

	filterGroupPeers(&components.Groups, components.Peers)
	filterPostureFailedPeers(&components.PostureFailedPeers, components.Policies, components.ResourcePoliciesMap, components.Peers)

	return components
}

func (nmd *NetworkMapData) getPeersGroupsPoliciesRoutes(
	peerID string,
	peerSSHEnabled bool,
	postureFailedPeers *map[string]map[string]struct{},
) (map[string]*nmdata.Peer, map[string]*nmdata.Group, []*nmdata.Policy, []*nmdata.Route, sshRequirements) {
	relevantPeerIDs := make(map[string]*nmdata.Peer, len(nmd.Peers)/4)
	relevantGroupIDs := make(map[string]*nmdata.Group, len(nmd.Groups)/4)
	relevantPolicies := make([]*nmdata.Policy, 0, len(nmd.Policies))
	relevantRoutes := make([]*nmdata.Route, 0, len(nmd.Routes))
	sshReqs := sshRequirements{neededGroupIDs: make(map[string]struct{})}

	relevantPeerIDs[peerID] = nmd.Peers[peerID]

	peerGroupSet := make(map[string]struct{}, 8)
	for groupID, group := range nmd.Groups {
		if slices.Contains(group.Peers, peerID) {
			relevantGroupIDs[groupID] = group
			peerGroupSet[groupID] = struct{}{}
		}
	}

	routeAccessControlGroups := make(map[string]struct{})
	for _, r := range nmd.Routes {
		if r == nil {
			continue
		}
		relevant := r.Peer == peerID
		if !relevant {
			for _, groupID := range r.PeerGroups {
				if _, ok := peerGroupSet[groupID]; ok {
					relevant = true
					break
				}
			}
		}
		if !relevant && r.Enabled {
			for _, groupID := range r.Groups {
				if _, ok := peerGroupSet[groupID]; ok {
					relevant = true
					break
				}
			}
		}
		if !relevant {
			continue
		}

		for _, groupID := range r.PeerGroups {
			relevantGroupIDs[groupID] = nmd.Groups[groupID]
		}
		for _, groupID := range r.Groups {
			relevantGroupIDs[groupID] = nmd.Groups[groupID]
		}
		if r.Enabled {
			for _, groupID := range r.AccessControlGroups {
				relevantGroupIDs[groupID] = nmd.Groups[groupID]
				routeAccessControlGroups[groupID] = struct{}{}
			}
		}

		if r.Peer != "" {
			if _, ok := nmd.ValidatedPeers[r.Peer]; ok {
				if p := nmd.Peers[r.Peer]; p != nil {
					relevantPeerIDs[r.Peer] = p
				}
			}
		}
		for _, groupID := range r.PeerGroups {
			g := nmd.Groups[groupID]
			if g == nil {
				continue
			}
			for _, pid := range g.Peers {
				if _, exists := relevantPeerIDs[pid]; exists {
					continue
				}
				if _, ok := nmd.ValidatedPeers[pid]; !ok {
					continue
				}
				if p := nmd.Peers[pid]; p != nil {
					relevantPeerIDs[pid] = p
				}
			}
		}
		relevantRoutes = append(relevantRoutes, r)
	}

	for _, policy := range nmd.Policies {
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
							relevantGroupIDs[srcGroupID] = nmd.Groups[srcGroupID]
						}
						for _, dstGroupID := range rule.Destinations {
							relevantGroupIDs[dstGroupID] = nmd.Groups[dstGroupID]
						}
						break
					}
				}
			}

			var sourcePeers, destinationPeers []string
			var peerInSources, peerInDestinations bool

			if rule.SourceResource.Type == string(types.ResourceTypePeer) && rule.SourceResource.ID != "" {
				sourcePeers = []string{rule.SourceResource.ID}
				if rule.SourceResource.ID == peerID {
					peerInSources = true
				}
			} else {
				sourcePeers, peerInSources = nmd.getPeersFromGroups(rule.Sources, peerID, policy.SourcePostureChecks, postureFailedPeers)
			}

			if rule.DestinationResource.Type == string(types.ResourceTypePeer) && rule.DestinationResource.ID != "" {
				destinationPeers = []string{rule.DestinationResource.ID}
				if rule.DestinationResource.ID == peerID {
					peerInDestinations = true
				}
			} else {
				destinationPeers, peerInDestinations = nmd.getPeersFromGroups(rule.Destinations, peerID, nil, postureFailedPeers)
			}

			if peerInSources {
				policyRelevant = true
				for _, pid := range destinationPeers {
					relevantPeerIDs[pid] = nmd.Peers[pid]
				}
				for _, dstGroupID := range rule.Destinations {
					relevantGroupIDs[dstGroupID] = nmd.Groups[dstGroupID]
				}
			}

			if peerInDestinations {
				policyRelevant = true
				for _, pid := range sourcePeers {
					relevantPeerIDs[pid] = nmd.Peers[pid]
				}
				for _, srcGroupID := range rule.Sources {
					relevantGroupIDs[srcGroupID] = nmd.Groups[srcGroupID]
				}

				if rule.Protocol == string(types.PolicyRuleProtocolNetbirdSSH) {
					switch {
					case len(rule.AuthorizedGroups) > 0:
						for groupID := range rule.AuthorizedGroups {
							sshReqs.neededGroupIDs[groupID] = struct{}{}
						}
					case rule.AuthorizedUser != "":
					default:
						sshReqs.needAllowedUserIDs = true
					}
				} else if nmdata.PolicyRuleImpliesLegacySSH(rule) && peerSSHEnabled {
					sshReqs.needAllowedUserIDs = true
				}
			}
		}
		if policyRelevant {
			relevantPolicies = append(relevantPolicies, policy)
		}
	}

	return relevantPeerIDs, relevantGroupIDs, relevantPolicies, relevantRoutes, sshReqs
}

func (nmd *NetworkMapData) getPeersFromGroups(groups []string, peerID string, sourcePostureChecksIDs []string,
	postureFailedPeers *map[string]map[string]struct{}) ([]string, bool) {
	peerInGroups := false
	filteredPeerIDs := make([]string, 0, len(groups))
	seenPeerIds := make(map[string]struct{}, len(groups))

	for _, gid := range groups {
		group := nmd.Groups[gid]
		if group == nil {
			continue
		}

		if group.IsGroupAll() || len(groups) == 1 {
			filteredPeerIDs = make([]string, 0, len(group.Peers))
			peerInGroups = false
			for _, pid := range group.Peers {
				peer, ok := nmd.Peers[pid]
				if !ok || peer == nil {
					continue
				}

				if _, ok := nmd.ValidatedPeers[peer.ID]; !ok {
					continue
				}

				isValid, pname := nmd.validatePostureChecksOnPeerGetFailed(sourcePostureChecksIDs, peer.ID)
				if !isValid && len(pname) > 0 {
					if _, ok := (*postureFailedPeers)[pname]; !ok {
						(*postureFailedPeers)[pname] = make(map[string]struct{})
					}
					(*postureFailedPeers)[pname][peer.ID] = struct{}{}
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
			peer, ok := nmd.Peers[pid]
			if !ok || peer == nil {
				continue
			}

			if _, ok := nmd.ValidatedPeers[peer.ID]; !ok {
				continue
			}

			isValid, pname := nmd.validatePostureChecksOnPeerGetFailed(sourcePostureChecksIDs, peer.ID)
			if !isValid && len(pname) > 0 {
				if _, ok := (*postureFailedPeers)[pname]; !ok {
					(*postureFailedPeers)[pname] = make(map[string]struct{})
				}
				(*postureFailedPeers)[pname][peer.ID] = struct{}{}
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

func (nmd *NetworkMapData) validatePostureChecksOnPeerGetFailed(sourcePostureChecksID []string, peerID string) (bool, string) {
	peer, ok := nmd.Peers[peerID]
	if !ok || peer == nil {
		return false, ""
	}

	for _, postureChecksID := range sourcePostureChecksID {
		postureChecks := nmd.PostureChecks[postureChecksID]
		if postureChecks == nil {
			continue
		}
		if !postureChecks.Passes(peer) {
			return false, postureChecksID
		}
	}
	return true, ""
}

func (nmd *NetworkMapData) getPostureValidPeersSaveFailed(inputPeers []string, postureChecksIDs []string, postureFailedPeers *map[string]map[string]struct{}) []string {
	var dest []string
	for _, peerID := range inputPeers {
		if _, validated := nmd.ValidatedPeers[peerID]; !validated {
			continue
		}
		valid, pname := nmd.validatePostureChecksOnPeerGetFailed(postureChecksIDs, peerID)
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

func (nmd *NetworkMapData) GetPeerGroups(peerID string) map[string]struct{} {
	groups := make(map[string]struct{})
	for groupID, group := range nmd.Groups {
		if slices.Contains(group.Peers, peerID) {
			groups[groupID] = struct{}{}
		}
	}
	return groups
}

func (nmd *NetworkMapData) getUniquePeerIDsFromGroupsIDs(groups []string) []string {
	peerIDs := make(map[string]struct{}, len(groups))
	for _, groupID := range groups {
		group := nmd.Groups[groupID]
		if group == nil {
			continue
		}

		if group.IsGroupAll() || len(groups) == 1 {
			return group.Peers
		}

		for _, peerID := range group.Peers {
			peerIDs[peerID] = struct{}{}
		}
	}

	ids := make([]string, 0, len(peerIDs))
	for peerID := range peerIDs {
		ids = append(ids, peerID)
	}

	return ids
}

func (nmd *NetworkMapData) getAllowedUserIDs() map[string]struct{} {
	return nmd.AllowedUserIDs
}

func (nmd *NetworkMapData) appliedZones(peerGroups map[string]struct{}) []nmdata.CustomZone {
	if len(peerGroups) == 0 {
		return nil
	}
	var out []nmdata.CustomZone
	for _, cand := range nmd.AppliedZoneCandidates {
		if peerInDistributionGroups(peerGroups, cand.DistributionGroups) {
			out = append(out, cand.Zone)
		}
	}
	return out
}

func (nmd *NetworkMapData) privateServiceZones(peerGroups map[string]struct{}) []nmdata.CustomZone {
	byApex := make(map[string]*nmdata.CustomZone)
	var order []string
	for _, cand := range nmd.PrivateServiceCandidates {
		if !peerInDistributionGroups(peerGroups, cand.AccessGroups) {
			continue
		}
		zone, exists := byApex[cand.Zone.Domain]
		if !exists {
			nz := nmdata.CustomZone{
				Domain:               cand.Zone.Domain,
				SearchDomainDisabled: cand.Zone.SearchDomainDisabled,
				NonAuthoritative:     cand.Zone.NonAuthoritative,
			}
			byApex[cand.Zone.Domain] = &nz
			zone = &nz
			order = append(order, cand.Zone.Domain)
		}
		zone.Records = append(zone.Records, cand.Zone.Records...)
	}

	var out []nmdata.CustomZone
	for _, apex := range order {
		zone := byApex[apex]
		if len(zone.Records) == 0 {
			continue
		}
		out = append(out, *zone)
	}
	return out
}

func peerInDistributionGroups(peerGroups map[string]struct{}, groups []string) bool {
	for _, g := range groups {
		if _, ok := peerGroups[g]; ok {
			return true
		}
	}
	return false
}

func filterGroupPeers(groups *map[string]*nmdata.Group, peers map[string]*nmdata.Peer) {
	for groupID, groupInfo := range *groups {
		filteredPeers := make([]string, 0, len(groupInfo.Peers))
		for _, pid := range groupInfo.Peers {
			if _, exists := peers[pid]; exists {
				filteredPeers = append(filteredPeers, pid)
			}
		}

		if len(filteredPeers) != len(groupInfo.Peers) {
			ng := groupInfo.Copy()
			ng.Peers = filteredPeers
			(*groups)[groupID] = ng
		}
	}
}

func filterPostureFailedPeers(postureFailedPeers *map[string]map[string]struct{}, policies []*nmdata.Policy, resourcePoliciesMap map[string][]*nmdata.Policy, peers map[string]*nmdata.Peer) {
	if len(*postureFailedPeers) == 0 {
		return
	}

	referencedPostureChecks := make(map[string]struct{})
	for _, policy := range policies {
		for _, checkID := range policy.SourcePostureChecks {
			referencedPostureChecks[checkID] = struct{}{}
		}
	}
	for _, resPolicies := range resourcePoliciesMap {
		for _, policy := range resPolicies {
			for _, checkID := range policy.SourcePostureChecks {
				referencedPostureChecks[checkID] = struct{}{}
			}
		}
	}

	for checkID, failedPeers := range *postureFailedPeers {
		if _, referenced := referencedPostureChecks[checkID]; !referenced {
			delete(*postureFailedPeers, checkID)
			continue
		}
		for peerID := range failedPeers {
			if _, exists := peers[peerID]; !exists {
				delete(failedPeers, peerID)
			}
		}
		if len(failedPeers) == 0 {
			delete(*postureFailedPeers, checkID)
		}
	}
}

func filterDNSRecordsByPeers(records []nmdata.SimpleRecord, peers map[string]*nmdata.Peer, includeIPv6 bool) []nmdata.SimpleRecord {
	if len(records) == 0 || len(peers) == 0 {
		return nil
	}

	peerIPs := make(map[string]struct{}, len(peers)*2)
	for _, peer := range peers {
		if peer == nil {
			continue
		}
		peerIPs[peer.IP.String()] = struct{}{}
		if includeIPv6 && peer.IPv6.IsValid() {
			peerIPs[peer.IPv6.String()] = struct{}{}
		}
	}

	filteredRecords := make([]nmdata.SimpleRecord, 0, len(records))
	for _, record := range records {
		if _, exists := peerIPs[record.RData]; exists {
			filteredRecords = append(filteredRecords, record)
		}
	}

	return filteredRecords
}

func filterGroupIDToUserIDs(fullMap map[string][]string, neededGroupIDs map[string]struct{}) map[string][]string {
	if len(neededGroupIDs) == 0 {
		return nil
	}

	filtered := make(map[string][]string, len(neededGroupIDs))
	for groupID := range neededGroupIDs {
		if users, ok := fullMap[groupID]; ok {
			filtered[groupID] = users
		}
	}
	return filtered
}
