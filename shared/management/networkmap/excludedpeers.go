package networkmap

import (
	"cmp"
	"math/bits"
	"slices"

	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/management/types"
)

// unvalidatedIndex ranks the existing peers the integrated validator did not
// validate in excluded-peer order, so a peer's exclusions mark them in a bitset and
// read them back sorted. byGroup holds the ranks of the members of every group that
// has such peers.
type unvalidatedIndex struct {
	peers   []*nmdata.Peer
	rank    map[string]int
	byGroup map[string][]int
}

// exclusions records, while a peer's components are computed, the peers that
// admission kept out of its view and whether the peer's own posture kept it out
// of a policy. Nothing is allocated until a peer is recorded.
type exclusions struct {
	// unvalidated is a bitset over the unvalidatedIndex ranks.
	unvalidated []uint64
	// postureFailures are the posture failures, keyed by check ID, of the source
	// sides whose peers the target would otherwise see.
	postureFailures []map[string]map[string]struct{}
	// postureChecksFailed is set when the target fails the source posture checks
	// of a policy it is a source of; it feeds the target's own exclusion reasons.
	postureChecksFailed bool
}

// unvalidatedPeers returns the account's unvalidated peer index, built once per
// NetworkMapData, or nil when every peer is validated.
func (nmd *NetworkMapData) unvalidatedPeers() *unvalidatedIndex {
	c := nmd.admissions()
	c.unvalidatedOnce.Do(func() {
		c.unvalidated = nmd.buildUnvalidatedIndex()
	})
	return c.unvalidated
}

func (nmd *NetworkMapData) buildUnvalidatedIndex() *unvalidatedIndex {
	var peers []*nmdata.Peer
	for pid, p := range nmd.Peers {
		if p == nil {
			continue
		}
		if _, validated := nmd.ValidatedPeers[pid]; !validated {
			peers = append(peers, p)
		}
	}
	if len(peers) == 0 {
		return nil
	}
	slices.SortFunc(peers, compareExcludedPeers)

	idx := &unvalidatedIndex{
		peers:   peers,
		rank:    make(map[string]int, len(peers)),
		byGroup: make(map[string][]int),
	}
	for i, p := range peers {
		idx.rank[p.ID] = i
	}
	for groupID, group := range nmd.Groups {
		if group == nil {
			continue
		}
		for _, pid := range group.Peers {
			if r, ok := idx.rank[pid]; ok {
				idx.byGroup[groupID] = append(idx.byGroup[groupID], r)
			}
		}
	}
	return idx
}

// compareExcludedPeers orders excluded peers by IP, then DNS label, then ID.
func compareExcludedPeers(a, b *nmdata.Peer) int {
	if c := a.IP.Compare(b.IP); c != 0 {
		return c
	}
	if c := cmp.Compare(a.DNSLabel, b.DNSLabel); c != 0 {
		return c
	}
	return cmp.Compare(a.ID, b.ID)
}

// markUnvalidated records the peer when the integrated validator did not validate it.
func (nmd *NetworkMapData) markUnvalidated(e *exclusions, pid string) {
	idx := nmd.unvalidatedPeers()
	if idx == nil {
		return
	}
	if r, ok := idx.rank[pid]; ok {
		e.markRank(idx, r)
	}
}

func (e *exclusions) markRank(idx *unvalidatedIndex, r int) {
	if e.unvalidated == nil {
		e.unvalidated = make([]uint64, (len(idx.peers)+63)/64)
	}
	e.unvalidated[r/64] |= 1 << (r % 64)
}

// nextUnvalidated returns the lowest marked rank at or above from, or -1.
func (e *exclusions) nextUnvalidated(from int) int {
	for w := from / 64; w < len(e.unvalidated); w++ {
		word := e.unvalidated[w]
		if w == from/64 {
			word &^= 1<<(from%64) - 1
		}
		if word != 0 {
			return w*64 + bits.TrailingZeros64(word)
		}
	}
	return -1
}

// collectUnvalidated records the members of a policy side that the integrated validator excluded.
func (nmd *NetworkMapData) collectUnvalidated(e *exclusions, groups []string, resource nmdata.Resource) {
	idx := nmd.unvalidatedPeers()
	if idx == nil {
		return
	}
	if isPeerResource(resource) {
		nmd.markUnvalidated(e, resource.ID)
		return
	}
	for _, gid := range groups {
		for _, r := range idx.byGroup[gid] {
			e.markRank(idx, r)
		}
	}
}

func (e *exclusions) addPostureFailures(failed map[string]map[string]struct{}) {
	if len(failed) > 0 {
		e.postureFailures = append(e.postureFailures, failed)
	}
}

// notePostureFailure sets postureChecksFailed when the peer is among the posture
// failures of a source side.
func (e *exclusions) notePostureFailure(failed map[string]map[string]struct{}, peerID string) {
	if e.postureChecksFailed {
		return
	}
	for _, peerIDs := range failed {
		if _, ok := peerIDs[peerID]; ok {
			e.postureChecksFailed = true
			return
		}
	}
}

// ownExclusionReasons returns why the server excludes the peer itself from other
// peers' maps, or nil. postureFailed reports whether the peer fails the source
// posture checks of a policy it is a source of.
func (nmd *NetworkMapData) ownExclusionReasons(peer *nmdata.Peer, postureFailed bool) []proto.ExclusionReason {
	// Appended in enum order, so the result is sorted and free of duplicates.
	var reasons []proto.ExclusionReason
	if types.PeerLoginExpired(peer, nmd.AccountSettings) {
		reasons = append(reasons, proto.ExclusionReason_ExclusionReasonLoginExpired)
	}
	if postureFailed {
		reasons = append(reasons, proto.ExclusionReason_ExclusionReasonPostureCheckFailed)
	}
	if _, validated := nmd.ValidatedPeers[peer.ID]; !validated {
		reasons = append(reasons, types.ValidationExclusionReason(peer.RequiresApproval))
	}
	return reasons
}

// setExcludedPeers fills the components' excluded peers from the recorded exclusions
// and the dropped login-expired peers, leaving out the target and every peer the
// components still hold. A peer the validator excluded is reported as pending
// approval or EDR non-compliant, a login-expired peer as expired, and the rest as
// failing posture checks.
//
// Admission keeps every unvalidated peer out of the components, so the three sets
// are disjoint and each marked unvalidated peer is excluded: the total is a bit
// count, and the bitset yields those peers already sorted, so the list is merged
// and capped without visiting the rest.
func (nmd *NetworkMapData) setExcludedPeers(c *types.NetworkMapComponents, e *exclusions, expired map[string]struct{}) {
	if e.unvalidated == nil && len(expired) == 0 && len(e.postureFailures) == 0 {
		return
	}

	idx := nmd.unvalidatedPeers()
	others := nmd.expiredAndPostureFailedPeers(c, e, expired)

	total := len(others)
	for _, word := range e.unvalidated {
		total += bits.OnesCount64(word)
	}
	if total == 0 {
		return
	}

	list := make([]types.ExcludedPeer, 0, min(total, types.MaxExcludedPeers))
	r, j := e.nextUnvalidated(0), 0
	for len(list) < cap(list) {
		if r < 0 || (j < len(others) && compareExcludedPeers(others[j].Peer, idx.peers[r]) < 0) {
			list = append(list, others[j])
			j++
			continue
		}
		p := idx.peers[r]
		r = e.nextUnvalidated(r + 1)
		list = append(list, types.ExcludedPeer{Peer: p, Reason: types.ValidationExclusionReason(p.RequiresApproval)})
	}
	c.ExcludedPeers = list
	c.ExcludedPeersTotal = total
}

// expiredAndPostureFailedPeers returns, sorted, the dropped login-expired peers and
// the posture-failed peers of the recorded source sides that the components do not
// hold. A posture-failed peer whose login expired is reported as expired.
func (nmd *NetworkMapData) expiredAndPostureFailedPeers(c *types.NetworkMapComponents, e *exclusions, expired map[string]struct{}) []types.ExcludedPeer {
	kept := func(pid string) bool {
		_, ok := c.Peers[pid]
		return ok || pid == c.PeerID
	}

	var others []types.ExcludedPeer
	for pid := range expired {
		if kept(pid) {
			continue
		}
		others = append(others, types.ExcludedPeer{Peer: nmd.Peers[pid], Reason: proto.ExclusionReason_ExclusionReasonLoginExpired})
	}

	var seen map[string]struct{}
	for _, failed := range e.postureFailures {
		for _, peerIDs := range failed {
			for pid := range peerIDs {
				if _, dropped := expired[pid]; dropped || kept(pid) {
					continue
				}
				if _, dup := seen[pid]; dup {
					continue
				}
				if seen == nil {
					seen = make(map[string]struct{})
				}
				seen[pid] = struct{}{}
				p := nmd.Peers[pid]
				reason := proto.ExclusionReason_ExclusionReasonPostureCheckFailed
				if c.IsLoginExpired(p) {
					reason = proto.ExclusionReason_ExclusionReasonLoginExpired
				}
				others = append(others, types.ExcludedPeer{Peer: p, Reason: reason})
			}
		}
	}

	slices.SortFunc(others, func(a, b types.ExcludedPeer) int {
		return compareExcludedPeers(a.Peer, b.Peer)
	})
	return others
}
