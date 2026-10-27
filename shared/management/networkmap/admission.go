package networkmap

import (
	"slices"
	"sync"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/types"
)

// admissionCache memoises the peer-independent parts of the components calculation:
// the posture-check verdicts and the admitted peers of every policy side. Its index is
// built once per NetworkMapData and every entry is filled on first use, so lookups
// take no lock and nothing is computed for checks or policies no peer needs. The
// NetworkMapData must not change once the index is built.
type admissionCache struct {
	policies map[*nmdata.Policy]*policyAdmission
	verdicts map[string]*postureVerdicts

	ruleFailuresOnce sync.Once
	ruleFailures     map[string]map[string]struct{}

	unvalidatedOnce sync.Once
	unvalidated     *unvalidatedIndex
}

// policyAdmission holds the admissions of one policy: the union of its source sides,
// used by the network resource loop, and the sides of each rule, in rule order.
type policyAdmission struct {
	sources admittedPeers
	rules   []ruleAdmission
}

type ruleAdmission struct {
	sources      admittedPeers
	destinations admittedPeers
}

// admittedPeers is the admission of one policy side: the peers that exist, are
// validated and pass the side's posture checks and, keyed by posture check ID, the
// peers a check rejected. Both are shared and must not be mutated.
type admittedPeers struct {
	once   sync.Once
	peers  []string
	failed map[string]map[string]struct{}
}

// postureVerdicts holds the results of one posture check keyed by peer ID. A nil
// map marks a check ID that resolves to no posture check, which passes.
type postureVerdicts struct {
	once    sync.Once
	results map[string]bool
}

func (nmd *NetworkMapData) admissions() *admissionCache {
	nmd.admissionsOnce.Do(func() {
		nmd.InjectProxyPolicies()
		c := &admissionCache{
			policies: make(map[*nmdata.Policy]*policyAdmission, len(nmd.Policies)),
			verdicts: make(map[string]*postureVerdicts, len(nmd.PostureChecks)),
		}
		for _, policy := range nmd.Policies {
			c.addPolicy(policy)
		}
		for _, policies := range nmd.ResourcePolicies {
			for _, policy := range policies {
				c.addPolicy(policy)
			}
		}
		for id := range nmd.PostureChecks {
			c.verdicts[id] = &postureVerdicts{}
		}
		nmd.admissionsIdx = c
	})
	return nmd.admissionsIdx
}

func (c *admissionCache) addPolicy(policy *nmdata.Policy) {
	if policy == nil {
		return
	}
	if _, ok := c.policies[policy]; ok {
		return
	}
	c.policies[policy] = &policyAdmission{rules: make([]ruleAdmission, len(policy.Rules))}
}

// ruleAdmissions returns the admitted source and destination peers of the policy's
// rule at index i.
func (nmd *NetworkMapData) ruleAdmissions(policy *nmdata.Policy, i int) (*admittedPeers, *admittedPeers) {
	rule := policy.Rules[i]
	ra := &nmd.admissions().policies[policy].rules[i]
	src := ra.sources.fill(func(failed *map[string]map[string]struct{}) []string {
		return nmd.admitSide(rule.Sources, rule.SourceResource, policy.SourcePostureChecks, failed)
	})
	dst := ra.destinations.fill(func(failed *map[string]map[string]struct{}) []string {
		return nmd.admitSide(rule.Destinations, rule.DestinationResource, nil, failed)
	})
	return src, dst
}

// resourcePolicySources returns the admitted source peers of a resource policy across
// all its rules, shared by every routing peer of the policy's resources.
func (nmd *NetworkMapData) resourcePolicySources(policy *nmdata.Policy) *admittedPeers {
	pa := nmd.admissions().policies[policy]
	return pa.sources.fill(func(failed *map[string]map[string]struct{}) []string {
		if resource := policy.Rules[0].SourceResource; isPeerResource(resource) {
			return nmd.getPeerFromResource(resource, policy.SourcePostureChecks, failed)
		}
		var admitted []string
		for _, pid := range nmd.getUniquePeerIDsFromGroupsIDs(policy.SourceGroups()) {
			if nmd.admitPolicyPeer(pid, policy.SourcePostureChecks, failed) {
				admitted = append(admitted, pid)
			}
		}
		return admitted
	})
}

func (a *admittedPeers) fill(admit func(failed *map[string]map[string]struct{}) []string) *admittedPeers {
	a.once.Do(func() {
		a.failed = make(map[string]map[string]struct{})
		a.peers = admit(&a.failed)
	})
	return a
}

func (nmd *NetworkMapData) admitSide(groups []string, resource nmdata.Resource, postureChecksIDs []string, failed *map[string]map[string]struct{}) []string {
	if isPeerResource(resource) {
		return nmd.getPeerFromResource(resource, postureChecksIDs, failed)
	}
	return nmd.getPeersFromGroups(groups, postureChecksIDs, failed)
}

// ruleFailures returns the posture failures of every enabled rule side. Every peer's
// rule loop walks all of them, so they are merged once per NetworkMapData.
func (nmd *NetworkMapData) ruleFailures() map[string]map[string]struct{} {
	c := nmd.admissions()
	c.ruleFailuresOnce.Do(func() {
		failures := make(map[string]map[string]struct{})
		for _, policy := range nmd.Policies {
			if policy == nil || !policy.Enabled {
				continue
			}
			for i, rule := range policy.Rules {
				if rule == nil || !rule.Enabled {
					continue
				}
				sources, destinations := nmd.ruleAdmissions(policy, i)
				mergePostureFailures(&failures, sources.failed)
				mergePostureFailures(&failures, destinations.failed)
			}
		}
		c.ruleFailures = failures
	})
	return c.ruleFailures
}

// sideAdmitsPeer reports whether the peer is an admitted member of a rule side,
// resolving membership like getPeersFromGroups without walking the group members.
func (nmd *NetworkMapData) sideAdmitsPeer(groups []string, resource nmdata.Resource, postureChecksIDs []string, peerID string, peerGroups map[string]struct{}) bool {
	member := false
	if isPeerResource(resource) {
		member = resource.ID == peerID
	} else {
		for _, gid := range groups {
			group := nmd.Groups[gid]
			if group == nil {
				continue
			}
			_, inGroup := peerGroups[gid]
			if group.IsGroupAll() || len(groups) == 1 {
				member = inGroup
				break
			}
			member = member || inGroup
		}
	}
	if !member {
		return false
	}
	admitted, _ := nmd.admitsPeer(peerID, postureChecksIDs)
	return admitted
}

// postureVerdict returns the cached result of a posture check for the peer and
// whether one is cached. The results of a check are evaluated on first use for the
// source peers of every enabled policy using it, or taken from PostureValidation
// when it was precomputed.
func (nmd *NetworkMapData) postureVerdict(postureChecksID, peerID string) (bool, bool) {
	v, ok := nmd.admissions().verdicts[postureChecksID]
	if !ok {
		return false, false
	}
	v.once.Do(func() {
		if results, seeded := nmd.PostureValidation[postureChecksID]; seeded {
			v.results = results
			return
		}
		v.results = nmd.evaluatePostureChecksForPeers(postureChecksID, nmd.postureCheckPeerIDs(postureChecksID))
	})
	if v.results == nil {
		return true, true
	}
	valid, found := v.results[peerID]
	return valid, found
}

// postureCheckPeerIDs collects the source peers of every enabled policy using the
// posture check.
func (nmd *NetworkMapData) postureCheckPeerIDs(postureChecksID string) map[string]struct{} {
	peerIDs := make(map[string]struct{})
	for _, policy := range nmd.Policies {
		if policy == nil || !policy.Enabled || !slices.Contains(policy.SourcePostureChecks, postureChecksID) {
			continue
		}
		for _, pid := range nmd.getUniquePeerIDsFromGroupsIDs(policy.SourceGroups()) {
			peerIDs[pid] = struct{}{}
		}
		for _, rule := range policy.Rules {
			if rule != nil && isPeerResource(rule.SourceResource) {
				peerIDs[rule.SourceResource.ID] = struct{}{}
			}
		}
	}
	return peerIDs
}

func isPeerResource(resource nmdata.Resource) bool {
	return resource.Type == string(types.ResourceTypePeer) && resource.ID != ""
}

func mergePostureFailures(dst *map[string]map[string]struct{}, failed map[string]map[string]struct{}) {
	for checkID, peerIDs := range failed {
		if _, ok := (*dst)[checkID]; !ok {
			(*dst)[checkID] = make(map[string]struct{}, len(peerIDs))
		}
		for pid := range peerIDs {
			(*dst)[checkID][pid] = struct{}{}
		}
	}
}
