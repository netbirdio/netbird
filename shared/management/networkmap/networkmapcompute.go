package networkmap

import (
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
	nmd.InjectProxyPolicies()

	forceRoutingPeerDNS := nmd.forcesRoutingPeerDNSResolution(peerID)

	peer := nmd.Peers[peerID]
	if peer == nil {
		return types.EmptyNetworkMapComponents(&types.NetworkMapComponents{
			PeerID:                        peerID,
			Network:                       nmd.Network,
			Peers:                         map[string]*nmdata.Peer{peerID: peer},
			ForceRoutingPeerDNSResolution: forceRoutingPeerDNS,
		})
	}

	if _, ok := nmd.ValidatedPeers[peerID]; !ok {
		return types.EmptyNetworkMapComponents(&types.NetworkMapComponents{
			PeerID:                        peerID,
			Network:                       nmd.Network,
			Peers:                         map[string]*nmdata.Peer{peerID: peer},
			ForceRoutingPeerDNSResolution: forceRoutingPeerDNS,
		})
	}

	components := &types.NetworkMapComponents{
		PeerID:                        peerID,
		Network:                       nmd.Network,
		AccountSettings:               nmd.AccountSettings,
		DNSSettings:                   nmd.DNSSettings,
		CustomZoneDomain:              peersCustomZone.Domain,
		NameServerGroups:              make([]*nmdata.NameServerGroup, 0),
		ResourcePoliciesMap:           make(map[string][]*nmdata.Policy),
		RoutersMap:                    make(map[string]map[string]*nmdata.NetworkRouter),
		NetworkResources:              make([]*nmdata.NetworkResource, 0),
		PostureFailedPeers:            make(map[string]map[string]struct{}, len(nmd.PostureChecks)),
		RouterPeers:                   make(map[string]*nmdata.Peer),
		NetworkXIDToPublicID:          nmd.NetworkXIDToPublicID,
		PostureCheckXIDToPublicID:     nmd.PostureCheckXIDToPublicID,
		ForceRoutingPeerDNSResolution: forceRoutingPeerDNS,
	}

	relevantPeers, relevantGroups, relevantPolicies, relevantRoutes, sshReqs := nmd.getPeersGroupsPoliciesRoutes(peerID, peer.SSHEnabled)

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
		if nsGroup != nil && nsGroup.Enabled {
			for _, gID := range nsGroup.Groups {
				if _, found := relevantGroups[gID]; found {
					components.NameServerGroups = append(components.NameServerGroups, nsGroup)
					break
				}
			}
		}
	}

	seenSourcePolicies := make(map[*nmdata.Policy]struct{})
	var sourceFailures []map[string]map[string]struct{}
	for _, resource := range nmd.NetworkResources {
		if resource == nil || !resource.Enabled {
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
			if policy == nil || !policy.Enabled || len(policy.Rules) == 0 || policy.Rules[0] == nil {
				continue
			}
			if addSourcePeers {
				if _, seen := seenSourcePolicies[policy]; !seen {
					seenSourcePolicies[policy] = struct{}{}
					sources := nmd.resourcePolicySources(policy)
					nmd.mergeSourcePeers(components, sources)
					sourceFailures = append(sourceFailures, sources.failed)
				}
			} else {
				peerInSources := false
				if policy.Rules[0].SourceResource.Type == string(types.ResourceTypePeer) && policy.Rules[0].SourceResource.ID != "" {
					peerInSources = policy.Rules[0].SourceResource.ID == peerID
				} else {
					for _, groupID := range policy.SourceGroups() {
						if _, ok := peerGroups[groupID]; ok {
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
				if rule == nil || !rule.Enabled {
					continue
				}
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
				p := nmd.Peers[peerIDKey]
				if p == nil {
					continue
				}
				// An unapproved peer must not carry traffic, so it is kept out of
				// RouterPeers as well: the envelope encoder indexes that map into
				// the wire peer table, from which the client restores every entry.
				if _, validated := nmd.ValidatedPeers[peerIDKey]; !validated {
					continue
				}
				if _, exists := components.RouterPeers[peerIDKey]; !exists {
					components.RouterPeers[peerIDKey] = p
				}
				if _, exists := components.Peers[peerIDKey]; !exists {
					components.Peers[peerIDKey] = p
				}
			}
			components.NetworkResources = append(components.NetworkResources, resource)
		}
	}

	filterGroupPeers(&components.Groups, components.Peers)
	nmd.collectPostureFailedPeers(components, sourceFailures)

	return components
}

func (nmd *NetworkMapData) getPeersGroupsPoliciesRoutes(
	peerID string,
	peerSSHEnabled bool,
) (map[string]*nmdata.Peer, map[string]*nmdata.Group, []*nmdata.Policy, []*nmdata.Route, sshRequirements) {
	relevantPeerIDs := make(map[string]*nmdata.Peer, len(nmd.Peers)/4)
	relevantGroupIDs := make(map[string]*nmdata.Group, len(nmd.Groups)/4)
	relevantPolicies := make([]*nmdata.Policy, 0, len(nmd.Policies))
	relevantRoutes := make([]*nmdata.Route, 0, len(nmd.Routes))
	sshReqs := sshRequirements{neededGroupIDs: make(map[string]struct{})}

	relevantPeerIDs[peerID] = nmd.Peers[peerID]

	peerGroupSet := nmd.GetPeerGroups(peerID)
	for groupID := range peerGroupSet {
		relevantGroupIDs[groupID] = nmd.Groups[groupID]
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
			if g := nmd.Groups[groupID]; g != nil {
				relevantGroupIDs[groupID] = g
			}
		}
		for _, groupID := range r.Groups {
			if g := nmd.Groups[groupID]; g != nil {
				relevantGroupIDs[groupID] = g
			}
		}
		if r.Enabled {
			for _, groupID := range r.AccessControlGroups {
				if g := nmd.Groups[groupID]; g != nil {
					relevantGroupIDs[groupID] = g
				}
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
		if policy == nil || !policy.Enabled {
			continue
		}

		policyRelevant := false
		for i, rule := range policy.Rules {
			if rule == nil || !rule.Enabled {
				continue
			}

			if len(routeAccessControlGroups) > 0 {
				for _, destGroupID := range rule.Destinations {
					if _, needed := routeAccessControlGroups[destGroupID]; needed {
						policyRelevant = true
						for _, srcGroupID := range rule.Sources {
							if g := nmd.Groups[srcGroupID]; g != nil {
								relevantGroupIDs[srcGroupID] = g
							}
						}
						for _, dstGroupID := range rule.Destinations {
							if g := nmd.Groups[dstGroupID]; g != nil {
								relevantGroupIDs[dstGroupID] = g
							}
						}
						break
					}
				}
			}

			sources, destinations := nmd.ruleAdmissions(policy, i)
			peerInSources := nmd.sideAdmitsPeer(rule.Sources, rule.SourceResource, policy.SourcePostureChecks, peerID, peerGroupSet)
			peerInDestinations := nmd.sideAdmitsPeer(rule.Destinations, rule.DestinationResource, nil, peerID, peerGroupSet)

			if peerInSources {
				policyRelevant = true
				for _, pid := range destinations.peers {
					relevantPeerIDs[pid] = nmd.Peers[pid]
				}
				for _, dstGroupID := range rule.Destinations {
					if g := nmd.Groups[dstGroupID]; g != nil {
						relevantGroupIDs[dstGroupID] = g
					}
				}
			}

			if peerInDestinations {
				policyRelevant = true
				for _, pid := range sources.peers {
					relevantPeerIDs[pid] = nmd.Peers[pid]
				}
				for _, srcGroupID := range rule.Sources {
					if g := nmd.Groups[srcGroupID]; g != nil {
						relevantGroupIDs[srcGroupID] = g
					}
				}
			}

			// SSH auth requirements are gathered whenever this peer serves
			// the rule. For bidirectional rules the peer-in-sources side
			// also serves inbound traffic and must be treated as a destination.
			if peerInDestinations || (rule.Bidirectional && peerInSources) {
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

// getPeersFromGroups returns the admitted members of a rule side given by groups.
// The All group, or a single group, alone decides the side. Posture failures are
// recorded in postureFailedPeers.
func (nmd *NetworkMapData) getPeersFromGroups(groups []string, sourcePostureChecksIDs []string,
	postureFailedPeers *map[string]map[string]struct{}) []string {
	filteredPeerIDs := make([]string, 0, len(groups))
	seenPeerIds := make(map[string]struct{}, len(groups))

	for _, gid := range groups {
		group := nmd.Groups[gid]
		if group == nil {
			continue
		}

		if group.IsGroupAll() || len(groups) == 1 {
			filteredPeerIDs = make([]string, 0, len(group.Peers))
			for _, pid := range group.Peers {
				if nmd.admitPolicyPeer(pid, sourcePostureChecksIDs, postureFailedPeers) {
					filteredPeerIDs = append(filteredPeerIDs, pid)
				}
			}
			return filteredPeerIDs
		}

		for _, pid := range group.Peers {
			if _, seen := seenPeerIds[pid]; seen {
				continue
			}
			seenPeerIds[pid] = struct{}{}
			if nmd.admitPolicyPeer(pid, sourcePostureChecksIDs, postureFailedPeers) {
				filteredPeerIDs = append(filteredPeerIDs, pid)
			}
		}
	}

	return filteredPeerIDs
}

// getPeerFromResource resolves a rule side that names a peer directly, admitting it
// like a member of a group holding only that peer.
func (nmd *NetworkMapData) getPeerFromResource(resource nmdata.Resource, sourcePostureChecksIDs []string,
	postureFailedPeers *map[string]map[string]struct{}) []string {
	if !nmd.admitPolicyPeer(resource.ID, sourcePostureChecksIDs, postureFailedPeers) {
		return nil
	}
	return []string{resource.ID}
}

// admitPolicyPeer is admitsPeer that records a failed posture check in postureFailedPeers.
func (nmd *NetworkMapData) admitPolicyPeer(pid string, sourcePostureChecksIDs []string, postureFailedPeers *map[string]map[string]struct{}) bool {
	admitted, failedCheck := nmd.admitsPeer(pid, sourcePostureChecksIDs)
	if failedCheck != "" {
		if _, ok := (*postureFailedPeers)[failedCheck]; !ok {
			(*postureFailedPeers)[failedCheck] = make(map[string]struct{})
		}
		(*postureFailedPeers)[failedCheck][pid] = struct{}{}
	}
	return admitted
}

// admitsPeer applies the per-peer admission of a rule side: the peer must exist, be
// validated and pass the rule's posture checks. It returns the first failed posture
// check ID, if any.
func (nmd *NetworkMapData) admitsPeer(pid string, sourcePostureChecksIDs []string) (bool, string) {
	peer, ok := nmd.Peers[pid]
	if !ok || peer == nil {
		return false, ""
	}

	if _, ok := nmd.ValidatedPeers[pid]; !ok {
		return false, ""
	}

	isValid, pname := nmd.validatePostureChecksOnPeerGetFailed(sourcePostureChecksIDs, pid)
	if !isValid && len(pname) > 0 {
		return false, pname
	}
	return true, ""
}

func (nmd *NetworkMapData) validatePostureChecksOnPeerGetFailed(sourcePostureChecksID []string, peerID string) (bool, string) {
	peer, ok := nmd.Peers[peerID]
	if !ok || peer == nil {
		return false, ""
	}

	for _, postureChecksID := range sourcePostureChecksID {
		if valid, cached := nmd.postureVerdict(postureChecksID, peerID); cached {
			if !valid {
				return false, postureChecksID
			}
			continue
		}

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

// PrecomputePostureValidation evaluates every posture check used by an enabled policy
// for the policy's source peers and stores the results in PostureValidation.
func (nmd *NetworkMapData) PrecomputePostureValidation() {
	if len(nmd.PostureChecks) == 0 {
		nmd.PostureValidation = nil
		return
	}

	results := make(map[string]map[string]bool)
	for _, policy := range nmd.Policies {
		if policy == nil || !policy.Enabled {
			continue
		}
		for _, postureChecksID := range policy.SourcePostureChecks {
			if _, done := results[postureChecksID]; !done {
				results[postureChecksID] = nmd.evaluatePostureChecksForPeers(postureChecksID, nmd.postureCheckPeerIDs(postureChecksID))
			}
		}
	}
	nmd.PostureValidation = results
}

func (nmd *NetworkMapData) evaluatePostureChecksForPeers(postureChecksID string, peerIDs map[string]struct{}) map[string]bool {
	postureChecks := nmd.PostureChecks[postureChecksID]
	if postureChecks == nil {
		return nil
	}

	checks := postureChecks.GetChecks()
	results := make(map[string]bool, len(peerIDs))
	for peerID := range peerIDs {
		peer := nmd.Peers[peerID]
		if peer == nil {
			continue
		}
		results[peerID] = nmdata.PassesChecks(checks, peer)
	}
	return results
}

// mergeSourcePeers adds the admitted source peers of a resource policy to the components.
func (nmd *NetworkMapData) mergeSourcePeers(components *types.NetworkMapComponents, sources *admittedPeers) {
	for _, pID := range sources.peers {
		if _, exists := components.Peers[pID]; !exists {
			components.Peers[pID] = nmd.Peers[pID]
		}
	}
}

// collectPostureFailedPeers sets the components' posture failures to those of every
// enabled rule side, of the given resource-policy sources and the ones already
// recorded, limited to the checks the components' policies reference and to the peers
// in the components. Each failure set is intersected with the components' peers from
// its smaller side, so the cost follows the peer's own map, not the account size.
func (nmd *NetworkMapData) collectPostureFailedPeers(components *types.NetworkMapComponents, sourceFailures []map[string]map[string]struct{}) {
	failures := append([]map[string]map[string]struct{}{nmd.ruleFailures(), components.PostureFailedPeers}, sourceFailures...)

	referenced := make(map[string]struct{})
	addReferenced := func(policy *nmdata.Policy) {
		if policy == nil {
			return
		}
		for _, checkID := range policy.SourcePostureChecks {
			referenced[checkID] = struct{}{}
		}
	}
	for _, policy := range components.Policies {
		addReferenced(policy)
	}
	for _, policies := range components.ResourcePoliciesMap {
		for _, policy := range policies {
			addReferenced(policy)
		}
	}

	result := make(map[string]map[string]struct{})
	for checkID := range referenced {
		var kept map[string]struct{}
		for _, failed := range failures {
			kept = addFailedPeersInMap(kept, failed[checkID], components.Peers)
		}
		if len(kept) > 0 {
			result[checkID] = kept
		}
	}
	components.PostureFailedPeers = result
}

// addFailedPeersInMap adds the failed peers that are in peers to kept, allocating kept
// on the first match, and returns it.
func addFailedPeersInMap(kept, failed map[string]struct{}, peers map[string]*nmdata.Peer) map[string]struct{} {
	add := func(pid string) {
		if kept == nil {
			kept = make(map[string]struct{})
		}
		kept[pid] = struct{}{}
	}
	if len(failed) <= len(peers) {
		for pid := range failed {
			if _, ok := peers[pid]; ok {
				add(pid)
			}
		}
		return kept
	}
	for pid := range peers {
		if _, ok := failed[pid]; ok {
			add(pid)
		}
	}
	return kept
}

// forcesRoutingPeerDNSResolution reports whether the given peer must run
// routing-peer DNS resolution regardless of the account-global
// RoutingPeerDNSResolutionEnabled setting: true when the peer routes a domain
// network resource targeted by an enabled reverse-proxy service, so the peer's
// DNS forwarder starts and can resolve the target for the embedded proxy peers.
func (nmd *NetworkMapData) forcesRoutingPeerDNSResolution(peerID string) bool {
	if len(nmd.ProxyTargetedDomainResourceIDs) == 0 {
		return false
	}

	for _, resource := range nmd.NetworkResources {
		if resource == nil || !resource.Enabled || resource.Type != string(types.ResourceTypeDomain) {
			continue
		}
		if _, ok := nmd.ProxyTargetedDomainResourceIDs[resource.ID]; !ok {
			continue
		}
		if _, isRouter := nmd.Routers[resource.NetworkID][peerID]; isRouter {
			return true
		}
	}

	return false
}

// GetPeerGroups returns the set of group IDs the peer belongs to. The
// underlying peer→groups index is built once per NetworkMapData and the
// returned set is shared — callers must not mutate it.
func (nmd *NetworkMapData) GetPeerGroups(peerID string) map[string]struct{} {
	nmd.peerGroupsOnce.Do(func() {
		idx := make(map[string]map[string]struct{}, len(nmd.Peers))
		for groupID, group := range nmd.Groups {
			if group == nil {
				continue
			}
			for _, pid := range group.Peers {
				set, ok := idx[pid]
				if !ok {
					set = make(map[string]struct{})
					idx[pid] = set
				}
				set[groupID] = struct{}{}
			}
		}
		nmd.peerGroupsIdx = idx
	})

	if set, ok := nmd.peerGroupsIdx[peerID]; ok {
		return set
	}
	return map[string]struct{}{}
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
