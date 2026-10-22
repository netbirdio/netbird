package networkmap

import (
	"slices"
	"strings"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/types"
)

type sshRequirements struct {
	neededGroupIDs     map[string]struct{}
	needAllowedUserIDs bool
}

// RequiresUsers reports whether the components of the given peers can ship
// user identities, the only use of AllowedUserIDs and GroupIDToUserIDs: an
// enabled NetBird SSH rule, or a rule implying legacy SSH while one of the
// peers runs the SSH server. The peers must be in Peers.
func (nmd *NetworkMapData) RequiresUsers(peerIDs ...string) bool {
	sshServer := false
	for _, peerID := range peerIDs {
		if p := nmd.Peers[peerID]; p != nil && p.SSHEnabled {
			sshServer = true
			break
		}
	}

	for _, policy := range nmd.Policies {
		if policy == nil || !policy.Enabled {
			continue
		}
		for _, rule := range policy.Rules {
			if rule == nil || !rule.Enabled {
				continue
			}
			if rule.Protocol == string(types.PolicyRuleProtocolNetbirdSSH) || (sshServer && nmdata.PolicyRuleImpliesLegacySSH(rule)) {
				return true
			}
		}
	}
	return false
}

// GetPeerNetworkMapComponents computes the peer's NetworkMapComponents from the
// slim twin store. It starts from the peer's groups and follows the account
// index to the policies, routes and network resources that reference the peer
// or its groups, expanding only the side of a rule facing away from the peer;
// objects that reference neither are never visited. The produced components
// hold twins.
func (nmd *NetworkMapData) GetPeerNetworkMapComponents(peerID string, peersZone *PeersZone) *types.NetworkMapComponents {
	nmd.componentsIndex()

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

	c := nmd.newPeerCalc(peerID, false)

	components := &types.NetworkMapComponents{
		PeerID:                        peerID,
		Network:                       nmd.Network,
		AccountSettings:               nmd.AccountSettings,
		DNSSettings:                   nmd.DNSSettings,
		CustomZoneDomain:              peersZone.Domain(),
		NameServerGroups:              make([]*nmdata.NameServerGroup, 0),
		ResourcePoliciesMap:           make(map[string][]*nmdata.Policy),
		RoutersMap:                    make(map[string]map[string]*nmdata.NetworkRouter),
		NetworkResources:              make([]*nmdata.NetworkResource, 0),
		PostureFailedPeers:            make(map[string]map[string]struct{}, len(nmd.PostureChecks)),
		RouterPeers:                   make(map[string]*nmdata.Peer),
		NetworkXIDToPublicID:          nmd.NetworkXIDToPublicID,
		PostureCheckXIDToPublicID:     nmd.PostureCheckXIDToPublicID,
		ForceRoutingPeerDNSResolution: forceRoutingPeerDNS,
		Peers:                         c.peers,
		Groups:                        c.groups,
	}

	components.Routes = c.collectRoutes()
	var sshReqs sshRequirements
	components.Policies, sshReqs = c.collectPolicies(peer.SSHEnabled)

	if len(sshReqs.neededGroupIDs) > 0 {
		components.GroupIDToUserIDs = filterGroupIDToUserIDs(nmd.GroupIDToUserIDs, sshReqs.neededGroupIDs)
	}
	if sshReqs.needAllowedUserIDs {
		components.AllowedUserIDs = nmd.getAllowedUserIDs()
	}

	components.AllDNSRecords = peersZone.recordsOf(c.peers, peer.SupportsIPv6() && peer.IPv6.IsValid())

	components.AccountZones = nmd.appliedZones(c.peerGroups)
	components.AccountZones = append(components.AccountZones, nmd.privateServiceZones(c.peerGroups)...)

	for _, nsGroup := range nmd.NameServerGroups {
		if nsGroup != nil && nsGroup.Enabled {
			for _, gID := range nsGroup.Groups {
				if _, found := c.groups[gID]; found {
					components.NameServerGroups = append(components.NameServerGroups, nsGroup)
					break
				}
			}
		}
	}

	c.collectNetworkResources(components)

	nmd.filterGroupPeers(components.Groups, components.Peers)
	if len(components.PostureFailedPeers) > 0 || len(nmd.policyPostureFailures()) > 0 {
		referencedChecks := referencedPostureChecks(components.Policies, components.ResourcePoliciesMap)
		nmd.addPolicyPostureFailures(components, referencedChecks)
		filterPostureFailedPeers(components.PostureFailedPeers, referencedChecks, components.Peers)
	}

	return components
}

// PeerClosure returns every peer the components of the given peers can hold,
// worked out from group memberships and references alone: the calculation runs
// with every referenced peer counted as existing, validated and passing its
// posture checks, which can only widen its result. Peer rows are not read, so
// the closure can be computed before they are loaded. It stops and reports
// false once the closure reaches limit peers; a limit of 0 means no limit.
func (nmd *NetworkMapData) PeerClosure(peerIDs []string, limit int) (map[string]struct{}, bool) {
	closure := make(map[string]struct{}, len(peerIDs))
	for _, peerID := range peerIDs {
		c := nmd.newPeerCalc(peerID, true)
		c.collectRoutes()
		c.collectPolicies(false)
		c.collectNetworkResources(&types.NetworkMapComponents{
			Peers:               c.peers,
			Groups:              c.groups,
			ResourcePoliciesMap: make(map[string][]*nmdata.Policy),
			RoutersMap:          make(map[string]map[string]*nmdata.NetworkRouter),
			RouterPeers:         make(map[string]*nmdata.Peer),
			PostureFailedPeers:  make(map[string]map[string]struct{}),
		})

		for id := range c.peers {
			closure[id] = struct{}{}
		}
		if limit > 0 && len(closure) >= limit {
			return nil, false
		}
	}
	return closure, true
}

// PeerSourcePostureChecks returns the posture checks of every enabled policy
// with an enabled rule naming the peer, directly or through one of its groups,
// as a source.
func (nmd *NetworkMapData) PeerSourcePostureChecks(peerID string) []*nmdata.PostureChecks {
	if len(nmd.PostureChecks) == 0 {
		return nil
	}

	idx := nmd.componentsIndex()
	peerGroups := nmd.GetPeerGroups(peerID)

	checks := make(map[string]*nmdata.PostureChecks)
	for _, i := range lookup(idx.policiesByPeer, idx.policiesByGroup, peerID, peerGroups) {
		policy := nmd.Policies[i]
		if len(policy.SourcePostureChecks) == 0 || !policyHasSourcePeer(policy, peerID, peerGroups) {
			continue
		}
		for _, checkID := range policy.SourcePostureChecks {
			if postureChecks := nmd.PostureChecks[checkID]; postureChecks != nil {
				checks[checkID] = postureChecks
			}
		}
	}

	result := make([]*nmdata.PostureChecks, 0, len(checks))
	for _, postureChecks := range checks {
		result = append(result, postureChecks)
	}
	return result
}

func policyHasSourcePeer(policy *nmdata.Policy, peerID string, peerGroups map[string]struct{}) bool {
	for _, rule := range policy.Rules {
		if rule == nil || !rule.Enabled {
			continue
		}
		if rule.SourceResource.Type == string(types.ResourceTypePeer) && rule.SourceResource.ID == peerID {
			return true
		}
		if anyInSet(rule.Sources, peerGroups) {
			return true
		}
	}
	return false
}

// peerCalc holds one peer's components calculation. A permissive calculation
// counts every referenced peer as existing, validated and passing its posture
// checks, which yields the widest set of peers the calculation can reach
// without reading any peer row.
type peerCalc struct {
	nmd        *NetworkMapData
	idx        *componentsIndex
	peerID     string
	peerGroups map[string]struct{}
	permissive bool

	peers  map[string]*nmdata.Peer
	groups map[string]*nmdata.Group

	routeAccessControlGroups map[string]struct{}
	expandedSides            map[string]struct{}
	expandedResourcePolicies map[string]struct{}
}

func (nmd *NetworkMapData) newPeerCalc(peerID string, permissive bool) *peerCalc {
	c := &peerCalc{
		nmd:                      nmd,
		idx:                      nmd.componentsIndex(),
		peerID:                   peerID,
		peerGroups:               nmd.GetPeerGroups(peerID),
		permissive:               permissive,
		peers:                    map[string]*nmdata.Peer{peerID: nmd.Peers[peerID]},
		groups:                   make(map[string]*nmdata.Group),
		routeAccessControlGroups: make(map[string]struct{}),
		expandedSides:            make(map[string]struct{}),
		expandedResourcePolicies: make(map[string]struct{}),
	}
	for groupID := range c.peerGroups {
		c.groups[groupID] = nmd.Groups[groupID]
	}
	return c
}

// admit reports whether a peer reached through a policy, route or router
// enters the components: it must exist, be validated and pass the posture
// checks. Failed checks are not recorded here; see addPolicyPostureFailures.
func (c *peerCalc) admit(peerID string, postureChecksIDs []string) bool {
	if c.permissive {
		return true
	}
	if c.nmd.Peers[peerID] == nil {
		return false
	}
	if _, ok := c.nmd.ValidatedPeers[peerID]; !ok {
		return false
	}
	valid, _ := c.nmd.validatePostureChecksOnPeerGetFailed(postureChecksIDs, peerID)
	return valid
}

func (c *peerCalc) addGroups(groupIDs []string) {
	for _, groupID := range groupIDs {
		if g := c.nmd.Groups[groupID]; g != nil {
			c.groups[groupID] = g
		}
	}
}

// collectRoutes adds the routes the peer serves or receives, their groups and
// their routing peers, and remembers their access control groups for
// collectPolicies.
func (c *peerCalc) collectRoutes() []*nmdata.Route {
	nmd := c.nmd
	candidates := lookup(c.idx.routesByPeer, c.idx.routesByGroup, c.peerID, c.peerGroups)
	routes := make([]*nmdata.Route, 0, len(candidates))

	for _, i := range candidates {
		r := nmd.Routes[i]
		relevant := r.Peer == c.peerID || anyInSet(r.PeerGroups, c.peerGroups) || (r.Enabled && anyInSet(r.Groups, c.peerGroups))
		if !relevant {
			continue
		}

		c.addGroups(r.PeerGroups)
		c.addGroups(r.Groups)
		if r.Enabled {
			c.addGroups(r.AccessControlGroups)
			for _, groupID := range r.AccessControlGroups {
				c.routeAccessControlGroups[groupID] = struct{}{}
			}
		}

		if r.Peer != "" && c.admit(r.Peer, nil) {
			c.peers[r.Peer] = nmd.Peers[r.Peer]
		}
		for _, groupID := range r.PeerGroups {
			g := nmd.Groups[groupID]
			if g == nil {
				continue
			}
			for _, pid := range g.Peers {
				if _, exists := c.peers[pid]; exists {
					continue
				}
				if c.admit(pid, nil) {
					c.peers[pid] = nmd.Peers[pid]
				}
			}
		}
		routes = append(routes, r)
	}

	return routes
}

// collectPolicies adds the policies with a rule that has the peer on one side,
// or that grants access to the access control groups of its routes. Of a rule
// holding the peer only the opposite side is expanded into peers.
func (c *peerCalc) collectPolicies(peerSSHEnabled bool) ([]*nmdata.Policy, sshRequirements) {
	nmd := c.nmd
	sshReqs := sshRequirements{neededGroupIDs: make(map[string]struct{})}

	candidates := lookup(c.idx.policiesByPeer, c.idx.policiesByGroup, c.peerID, c.peerGroups)
	if len(c.routeAccessControlGroups) > 0 {
		for groupID := range c.routeAccessControlGroups {
			candidates = append(candidates, c.idx.policiesByGroup[groupID]...)
		}
		candidates = sortedUnique(candidates)
	}

	policies := make([]*nmdata.Policy, 0, len(candidates))
	for _, i := range candidates {
		policy := nmd.Policies[i]
		policyRelevant := false

		for _, rule := range policy.Rules {
			if rule == nil || !rule.Enabled {
				continue
			}

			if len(c.routeAccessControlGroups) > 0 && anyInSet(rule.Destinations, c.routeAccessControlGroups) {
				policyRelevant = true
				c.addGroups(rule.Sources)
				c.addGroups(rule.Destinations)
			}

			peerInSources := c.sideHoldsPeer(rule.Sources, rule.SourceResource) && c.admit(c.peerID, policy.SourcePostureChecks)
			peerInDestinations := c.sideHoldsPeer(rule.Destinations, rule.DestinationResource)

			if peerInSources {
				policyRelevant = true
				c.addSidePeers(rule.Destinations, rule.DestinationResource, nil)
				c.addGroups(rule.Destinations)
			}

			if peerInDestinations {
				policyRelevant = true
				c.addSidePeers(rule.Sources, rule.SourceResource, policy.SourcePostureChecks)
				c.addGroups(rule.Sources)

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
			policies = append(policies, policy)
		}
	}

	return policies, sshReqs
}

// sideHoldsPeer reports whether a rule side contains the peer. A side naming a
// peer resource holds only that peer. Otherwise the first group named "All",
// or the only group of the side, decides alone, as getPeersFromGroups expands
// it; else any of the groups does.
func (c *peerCalc) sideHoldsPeer(groupIDs []string, resource nmdata.Resource) bool {
	if isPeerResource(resource) {
		return resource.ID == c.peerID
	}
	if g := c.decidingGroup(groupIDs); g != nil {
		_, ok := c.peerGroups[g.ID]
		return ok
	}
	return anyInSet(groupIDs, c.peerGroups)
}

// addSidePeers adds the admitted peers of a rule side, expanded the way
// sideHoldsPeer reads it. A group is expanded at most once per posture check
// list.
func (c *peerCalc) addSidePeers(groupIDs []string, resource nmdata.Resource, postureChecksIDs []string) {
	if isPeerResource(resource) {
		c.addPolicyPeer(resource.ID, postureChecksIDs)
		return
	}
	if g := c.decidingGroup(groupIDs); g != nil {
		c.addGroupPeers(g, postureChecksIDs)
		return
	}
	for _, groupID := range groupIDs {
		if g := c.nmd.Groups[groupID]; g != nil {
			c.addGroupPeers(g, postureChecksIDs)
		}
	}
}

// decidingGroup returns the group that alone makes up a rule side: the first
// existing group that is "All" or the side's only group.
func (c *peerCalc) decidingGroup(groupIDs []string) *nmdata.Group {
	for _, groupID := range groupIDs {
		g := c.nmd.Groups[groupID]
		if g == nil {
			continue
		}
		if g.IsGroupAll() || len(groupIDs) == 1 {
			return g
		}
	}
	return nil
}

func (c *peerCalc) addGroupPeers(g *nmdata.Group, postureChecksIDs []string) {
	key := g.ID
	if len(postureChecksIDs) > 0 {
		key += "\x00" + strings.Join(postureChecksIDs, "\x00")
	}
	if _, done := c.expandedSides[key]; done {
		return
	}
	c.expandedSides[key] = struct{}{}

	for _, pid := range g.Peers {
		c.addPolicyPeer(pid, postureChecksIDs)
	}
}

func (c *peerCalc) addPolicyPeer(peerID string, postureChecksIDs []string) {
	if peerID == c.peerID {
		return
	}
	if _, exists := c.peers[peerID]; exists {
		return
	}
	if c.admit(peerID, postureChecksIDs) {
		c.peers[peerID] = c.nmd.Peers[peerID]
	}
}

// collectNetworkResources adds the network resources the peer routes or may
// access, with their policies, routers and the peers on the other end.
func (c *peerCalc) collectNetworkResources(components *types.NetworkMapComponents) {
	nmd := c.nmd

	candidates := lookup(c.idx.resourcesByPeer, c.idx.resourcesByGroup, c.peerID, c.peerGroups)
	for _, networkID := range c.idx.networksByRouter[c.peerID] {
		candidates = append(candidates, c.idx.resourcesByNetwork[networkID]...)
	}
	candidates = sortedUnique(candidates)

	for _, i := range candidates {
		resource := nmd.NetworkResources[i]

		policies, exists := nmd.ResourcePolicies[resource.ID]
		if !exists {
			continue
		}

		addSourcePeers := false

		networkRoutingPeers, routerExists := nmd.Routers[resource.NetworkID]
		if routerExists {
			if _, ok := networkRoutingPeers[c.peerID]; ok {
				addSourcePeers = true
			}
		}

		for _, policy := range policies {
			if policy == nil || !policy.Enabled || len(policy.Rules) == 0 || policy.Rules[0] == nil {
				continue
			}
			if addSourcePeers {
				c.addResourcePolicySources(policy, components)
			} else {
				var peerInSources bool
				if isPeerResource(policy.Rules[0].SourceResource) {
					peerInSources = policy.Rules[0].SourceResource.ID == c.peerID
				} else {
					peerInSources = anyInSet(policy.SourceGroups(), c.peerGroups)
				}
				if !peerInSources {
					continue
				}
				if !c.permissive {
					isValid, pname := nmd.validatePostureChecksOnPeerGetFailed(policy.SourcePostureChecks, c.peerID)
					if !isValid && len(pname) > 0 {
						if _, ok := components.PostureFailedPeers[pname]; !ok {
							components.PostureFailedPeers[pname] = make(map[string]struct{})
						}
						components.PostureFailedPeers[pname][c.peerID] = struct{}{}
						continue
					}
				}
				addSourcePeers = true
			}

			for _, rule := range policy.Rules {
				if rule == nil || !rule.Enabled {
					continue
				}
				c.addGroups(rule.Sources)
				c.addGroups(rule.Destinations)
			}
			components.ResourcePoliciesMap[resource.ID] = policies
		}

		if addSourcePeers {
			components.RoutersMap[resource.NetworkID] = networkRoutingPeers
			for peerIDKey := range networkRoutingPeers {
				// An unapproved peer must not carry traffic, so it is kept out of
				// RouterPeers as well: the envelope encoder indexes that map into
				// the wire peer table, from which the client restores every entry.
				if !c.admit(peerIDKey, nil) {
					continue
				}
				p := nmd.Peers[peerIDKey]
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
}

// addResourcePolicySources adds the admitted source peers of a resource policy
// the peer routes, recording failed posture checks. A policy shared by several
// resources is expanded once.
func (c *peerCalc) addResourcePolicySources(policy *nmdata.Policy, components *types.NetworkMapComponents) {
	if policy.ID != "" {
		if _, done := c.expandedResourcePolicies[policy.ID]; done {
			return
		}
		c.expandedResourcePolicies[policy.ID] = struct{}{}
	}

	var peers []string
	if isPeerResource(policy.Rules[0].SourceResource) {
		peers = []string{policy.Rules[0].SourceResource.ID}
	} else {
		peers = c.nmd.getUniquePeerIDsFromGroupsIDs(policy.SourceGroups())
	}

	if !c.permissive {
		peers = c.nmd.getPostureValidPeersSaveFailed(peers, policy.SourcePostureChecks, &components.PostureFailedPeers)
	}
	for _, pID := range peers {
		if _, exists := components.Peers[pID]; !exists {
			components.Peers[pID] = c.nmd.Peers[pID]
		}
	}
}

// policyPostureFailures returns, per posture check, the peers that fail it as
// the first failing check of an enabled policy whose enabled rule has them as
// a source. Every peer's components start from this same record, so it is
// built once, with the same admission the rule sides use.
func (nmd *NetworkMapData) policyPostureFailures() map[string]map[string]struct{} {
	nmd.postureFailuresOnce.Do(func() {
		failures := make(map[string]map[string]struct{})
		evaluated := make(map[string]struct{})
		for _, policy := range nmd.Policies {
			if policy == nil || !policy.Enabled || len(policy.SourcePostureChecks) == 0 {
				continue
			}
			checksKey := strings.Join(policy.SourcePostureChecks, "\x00")
			for _, rule := range policy.Rules {
				if rule == nil || !rule.Enabled {
					continue
				}
				if isPeerResource(rule.SourceResource) {
					nmd.getPeerFromResource(rule.SourceResource, "", policy.SourcePostureChecks, &failures)
					continue
				}
				key := strings.Join(rule.Sources, "\x00") + "\x01" + checksKey
				if _, done := evaluated[key]; done {
					continue
				}
				evaluated[key] = struct{}{}
				nmd.getPeersFromGroups(rule.Sources, "", policy.SourcePostureChecks, &failures)
			}
		}
		nmd.postureFailures = failures
	})
	return nmd.postureFailures
}

// addPolicyPostureFailures adds the policy posture failures of the component
// peers for the referenced posture checks, iterating whichever side is smaller.
func (nmd *NetworkMapData) addPolicyPostureFailures(components *types.NetworkMapComponents, referencedChecks map[string]struct{}) {
	if len(referencedChecks) == 0 {
		return
	}

	failures := nmd.policyPostureFailures()
	for checkID := range referencedChecks {
		failed := failures[checkID]
		if len(failed) == 0 {
			continue
		}

		var matched []string
		if len(failed) <= len(components.Peers) {
			for peerID := range failed {
				if _, ok := components.Peers[peerID]; ok {
					matched = append(matched, peerID)
				}
			}
		} else {
			for peerID := range components.Peers {
				if _, ok := failed[peerID]; ok {
					matched = append(matched, peerID)
				}
			}
		}
		if len(matched) == 0 {
			continue
		}

		set := components.PostureFailedPeers[checkID]
		if set == nil {
			set = make(map[string]struct{}, len(matched))
			components.PostureFailedPeers[checkID] = set
		}
		for _, peerID := range matched {
			set[peerID] = struct{}{}
		}
	}
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
				if !nmd.admitPolicyPeer(pid, sourcePostureChecksIDs, postureFailedPeers) {
					continue
				}

				if pid == peerID {
					peerInGroups = true
					continue
				}

				filteredPeerIDs = append(filteredPeerIDs, pid)
			}
			return filteredPeerIDs, peerInGroups
		}

		for _, pid := range group.Peers {
			if _, seen := seenPeerIds[pid]; seen {
				continue
			}
			seenPeerIds[pid] = struct{}{}
			if !nmd.admitPolicyPeer(pid, sourcePostureChecksIDs, postureFailedPeers) {
				continue
			}

			if pid == peerID {
				peerInGroups = true
				continue
			}

			filteredPeerIDs = append(filteredPeerIDs, pid)
		}
	}

	return filteredPeerIDs, peerInGroups
}

// getPeerFromResource resolves a rule side that names a peer directly, admitting it
// like a member of a group holding only that peer.
func (nmd *NetworkMapData) getPeerFromResource(resource nmdata.Resource, peerID string, sourcePostureChecksIDs []string,
	postureFailedPeers *map[string]map[string]struct{}) ([]string, bool) {
	if !nmd.admitPolicyPeer(resource.ID, sourcePostureChecksIDs, postureFailedPeers) {
		return nil, false
	}
	if resource.ID == peerID {
		return nil, true
	}
	return []string{resource.ID}, false
}

// admitPolicyPeer applies the per-peer admission of a rule side: the peer must exist,
// be validated and pass the rule's posture checks. A failed check is recorded in
// postureFailedPeers.
func (nmd *NetworkMapData) admitPolicyPeer(pid string, sourcePostureChecksIDs []string, postureFailedPeers *map[string]map[string]struct{}) bool {
	peer, ok := nmd.Peers[pid]
	if !ok || peer == nil {
		return false
	}

	if _, ok := nmd.ValidatedPeers[pid]; !ok {
		return false
	}

	isValid, pname := nmd.validatePostureChecksOnPeerGetFailed(sourcePostureChecksIDs, pid)
	if !isValid && len(pname) > 0 {
		if _, ok := (*postureFailedPeers)[pname]; !ok {
			(*postureFailedPeers)[pname] = make(map[string]struct{})
		}
		(*postureFailedPeers)[pname][pid] = struct{}{}
		return false
	}
	return true
}

func (nmd *NetworkMapData) validatePostureChecksOnPeerGetFailed(sourcePostureChecksID []string, peerID string) (bool, string) {
	peer, ok := nmd.Peers[peerID]
	if !ok || peer == nil {
		return false, ""
	}

	for _, postureChecksID := range sourcePostureChecksID {
		if valid, cached := nmd.cachedPostureCheckResult(postureChecksID, peerID); cached {
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

func (nmd *NetworkMapData) PrecomputePostureValidation() {
	if len(nmd.PostureChecks) == 0 {
		nmd.PostureValidation = nil
		return
	}

	checkPeerIDs := make(map[string]map[string]struct{})
	for _, policy := range nmd.Policies {
		if policy == nil || !policy.Enabled || len(policy.SourcePostureChecks) == 0 {
			continue
		}

		groupPeerIDs := nmd.getUniquePeerIDsFromGroupsIDs(policy.SourceGroups())
		for _, postureChecksID := range policy.SourcePostureChecks {
			set := checkPeerIDs[postureChecksID]
			if set == nil {
				set = make(map[string]struct{}, len(groupPeerIDs))
				checkPeerIDs[postureChecksID] = set
			}
			for _, pid := range groupPeerIDs {
				set[pid] = struct{}{}
			}
			for _, rule := range policy.Rules {
				if rule == nil {
					continue
				}
				if rule.SourceResource.Type == string(types.ResourceTypePeer) && rule.SourceResource.ID != "" {
					set[rule.SourceResource.ID] = struct{}{}
				}
			}
		}
	}

	results := make(map[string]map[string]bool, len(checkPeerIDs))
	for postureChecksID, peerIDs := range checkPeerIDs {
		results[postureChecksID] = nmd.evaluatePostureChecksForPeers(postureChecksID, peerIDs)
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

func (nmd *NetworkMapData) cachedPostureCheckResult(postureChecksID, peerID string) (bool, bool) {
	results, ok := nmd.PostureValidation[postureChecksID]
	if !ok {
		return false, false
	}
	if results == nil {
		return true, true
	}
	valid, found := results[peerID]
	return valid, found
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
		if pname == "" {
			continue
		}
		if _, ok := (*postureFailedPeers)[pname]; !ok {
			(*postureFailedPeers)[pname] = make(map[string]struct{})
		}
		(*postureFailedPeers)[pname][peerID] = struct{}{}
	}
	return dest
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

	idx := nmd.componentsIndex()
	for _, networkID := range idx.networksByRouter[peerID] {
		for _, i := range idx.resourcesByNetwork[networkID] {
			resource := nmd.NetworkResources[i]
			if resource.Type != string(types.ResourceTypeDomain) {
				continue
			}
			if _, ok := nmd.ProxyTargetedDomainResourceIDs[resource.ID]; ok {
				return true
			}
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

// groupMembersAmong returns the peers that are members of the group, in the
// group's member order.
func (nmd *NetworkMapData) groupMembersAmong(groupID string, peers map[string]*nmdata.Peer) []string {
	type member struct {
		position int
		id       string
	}

	positions := nmd.memberPositions()[groupID]
	members := make([]member, 0, len(peers))
	for pid := range peers {
		if position, ok := positions[pid]; ok {
			members = append(members, member{position: position, id: pid})
		}
	}
	slices.SortFunc(members, func(a, b member) int { return a.position - b.position })

	ids := make([]string, len(members))
	for i, m := range members {
		ids[i] = m.id
	}
	return ids
}

// memberPositions returns, per group, the position of each member in the
// group's peer list. It is built once per NetworkMapData and shared.
func (nmd *NetworkMapData) memberPositions() map[string]map[string]int {
	nmd.memberPositionsOnce.Do(func() {
		positions := make(map[string]map[string]int, len(nmd.Groups))
		for groupID, group := range nmd.Groups {
			if group == nil {
				continue
			}
			members := make(map[string]int, len(group.Peers))
			for i, pid := range group.Peers {
				if _, seen := members[pid]; !seen {
					members[pid] = i
				}
			}
			positions[groupID] = members
		}
		nmd.memberPositionsIdx = positions
	})
	return nmd.memberPositionsIdx
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

// filterGroupPeers trims every group to the component peers, keeping the
// group's member order. A group many times larger than the component peers is
// rebuilt from them through the member positions instead of being scanned.
func (nmd *NetworkMapData) filterGroupPeers(groups map[string]*nmdata.Group, peers map[string]*nmdata.Peer) {
	for groupID, group := range groups {
		var filteredPeers []string
		if len(peers)*4 < len(group.Peers) {
			filteredPeers = nmd.groupMembersAmong(groupID, peers)
		} else {
			filteredPeers = make([]string, 0, len(group.Peers))
			for _, pid := range group.Peers {
				if _, exists := peers[pid]; exists {
					filteredPeers = append(filteredPeers, pid)
				}
			}
		}

		if len(filteredPeers) != len(group.Peers) {
			ng := group.Copy()
			ng.Peers = filteredPeers
			groups[groupID] = ng
		}
	}
}

// referencedPostureChecks returns the posture checks the component policies
// and resource policies reference.
func referencedPostureChecks(policies []*nmdata.Policy, resourcePoliciesMap map[string][]*nmdata.Policy) map[string]struct{} {
	referenced := make(map[string]struct{})
	for _, policy := range policies {
		for _, checkID := range policy.SourcePostureChecks {
			referenced[checkID] = struct{}{}
		}
	}
	for _, resPolicies := range resourcePoliciesMap {
		for _, policy := range resPolicies {
			if policy == nil {
				continue
			}
			for _, checkID := range policy.SourcePostureChecks {
				referenced[checkID] = struct{}{}
			}
		}
	}
	return referenced
}

func filterPostureFailedPeers(postureFailedPeers map[string]map[string]struct{}, referencedChecks map[string]struct{}, peers map[string]*nmdata.Peer) {
	for checkID, failedPeers := range postureFailedPeers {
		if _, referenced := referencedChecks[checkID]; !referenced {
			delete(postureFailedPeers, checkID)
			continue
		}
		for peerID := range failedPeers {
			if _, exists := peers[peerID]; !exists {
				delete(failedPeers, peerID)
			}
		}
		if len(failedPeers) == 0 {
			delete(postureFailedPeers, checkID)
		}
	}
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
