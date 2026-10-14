//go:build (linux && !android) || freebsd

package configurer

import (
	"net"
	"net/netip"
	"slices"
	"sync"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// allowedIPStore mirrors the allowed IPs configured on each peer of a device.
//
// A configurer is the only writer of its device's peer set, so the mirror is authoritative
// by construction. It spares the paths that have to rewrite one peer's allowed IPs a full
// device dump just to recover prefixes the process already configured itself.
//
// An allowed IP belongs to exactly one peer: configuring a prefix on a peer takes it away
// from whichever peer held it before, and the configurer leaves that handover to the device
// rather than removing the prefix from the previous holder itself. The store tracks the
// owner of each prefix and performs the same handover, so rewriting one peer's list never
// takes a prefix back from the peer that owns it now.
//
// Its own lock guards the map alone, not the device write it accompanies. Consistency
// between the two rests on the caller serializing every configurer call, which WGIface
// does with its mutex; two unserialized writers would interleave a device write with the
// record of a different one.
//
// An operator reconfiguring the device out of band, through `wg set` or the UAPI socket,
// is the one way the mirror can still go stale. A peer missing from it falls back to the
// device, which reseats that peer's prefixes and their ownership; a peer that is present
// does not, so one recorded from empty while the device already held prefixes keeps only
// what was recorded, and the next endpoint removal drops the rest.
type allowedIPStore struct {
	mu     sync.RWMutex
	peers  map[wgtypes.Key][]netip.Prefix
	owners map[netip.Prefix]wgtypes.Key
}

func newAllowedIPStore() *allowedIPStore {
	return &allowedIPStore{
		peers:  make(map[wgtypes.Key][]netip.Prefix),
		owners: make(map[netip.Prefix]wgtypes.Key),
	}
}

// get returns the prefixes recorded for a peer, and whether the peer is known at all.
// The caller receives a copy and may retain or modify it freely.
func (s *allowedIPStore) get(key wgtypes.Key) ([]netip.Prefix, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	prefixes, ok := s.peers[key]
	if !ok {
		return nil, false
	}
	return slices.Clone(prefixes), true
}

// set replaces the prefixes recorded for a peer.
func (s *allowedIPStore) set(key wgtypes.Key, prefixes []netip.Prefix) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := key
	s.releaseLocked(k)

	normalized := normalizePrefixes(prefixes)
	for _, prefix := range normalized {
		s.claimLocked(k, prefix)
	}
	s.peers[k] = normalized
}

// add records prefixes on a peer without dropping the ones already there, matching the
// union semantics of a peer update that does not replace its allowed IPs. It records the
// peer if it is not known yet, so it belongs to the operations that create a peer on the
// device rather than to the update-only ones.
func (s *allowedIPStore) add(key wgtypes.Key, prefixes []netip.Prefix) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.mergeLocked(key, prefixes)
}

// addExisting is add for an update-only device operation. Such an operation is a silent
// no-op when the peer is absent, so recording a peer here would leave the store claiming
// prefixes the device never took, and the peer would then be recreated by the next endpoint
// removal, stealing those allowed IPs from the peer that legitimately holds them.
func (s *allowedIPStore) addExisting(key wgtypes.Key, prefixes []netip.Prefix) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := key
	if _, ok := s.peers[k]; !ok {
		return
	}
	s.mergeLocked(k, prefixes)
}

// ensure records a peer with no prefixes unless it is already known. A device operation
// that is not update-only creates the peer when it is absent, so it has to be recorded even
// when it configures nothing else; otherwise the peer exists on the device while the store
// treats it as unknown, and a prefix later handed over to it is not accounted for.
func (s *allowedIPStore) ensure(key wgtypes.Key) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := key
	if _, ok := s.peers[k]; !ok {
		s.peers[k] = nil
	}
}

// forget drops every prefix recorded for a peer.
func (s *allowedIPStore) forget(key wgtypes.Key) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := key
	s.releaseLocked(k)
	delete(s.peers, k)
}

// reset drops every peer, mirroring a device reconfiguration that replaces the peer set.
func (s *allowedIPStore) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.peers = make(map[wgtypes.Key][]netip.Prefix)
	s.owners = make(map[netip.Prefix]wgtypes.Key)
}

// mergeLocked unions normalized prefixes into a peer and transfers their ownership.
// The caller must hold s.mu for writing.
func (s *allowedIPStore) mergeLocked(k wgtypes.Key, prefixes []netip.Prefix) {
	merged := s.peers[k]
	for _, prefix := range prefixes {
		prefix = normalizePrefix(prefix)
		s.claimLocked(k, prefix)
		if !slices.Contains(merged, prefix) {
			merged = append(merged, prefix)
		}
	}
	s.peers[k] = merged
}

// claimLocked hands a prefix over to a peer, taking it from its previous owner the way the
// device does when the same prefix is configured on a second peer.
func (s *allowedIPStore) claimLocked(k wgtypes.Key, prefix netip.Prefix) {
	if owner, ok := s.owners[prefix]; ok && owner != k {
		s.peers[owner] = slices.DeleteFunc(s.peers[owner], func(p netip.Prefix) bool {
			return p == prefix
		})
	}
	s.owners[prefix] = k
}

// releaseLocked drops a peer's claim on every prefix it currently holds.
func (s *allowedIPStore) releaseLocked(k wgtypes.Key) {
	for _, prefix := range s.peers[k] {
		if s.owners[prefix] == k {
			delete(s.owners, prefix)
		}
	}
}

// ipNetsToPrefixes converts addresses read back from a device. Unmap keeps a v4-mapped v6
// address comparable to the plain v4 prefix the configurer was given.
func ipNetsToPrefixes(ipNets []net.IPNet) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(ipNets))
	for _, ipNet := range ipNets {
		addr, ok := netip.AddrFromSlice(ipNet.IP)
		if !ok {
			continue
		}

		ones, maskBits := ipNet.Mask.Size()
		// A device may report a v4 prefix as a v4-mapped address. Align the address form with
		// the mask rather than unmapping on sight: a 32 bit mask always describes v4, while a
		// 128 bit mask describes v4 only when it covers the mapped prefix, so a genuine v6
		// prefix inside the mapped range stays v6 instead of being dropped as invalid.
		if addr.Is4In6() {
			switch {
			case maskBits == 32:
				addr = addr.Unmap()
			case maskBits == 128 && ones >= 96:
				addr, ones = addr.Unmap(), ones-96
			}
		}

		prefix := netip.PrefixFrom(addr, ones)
		if !prefix.IsValid() {
			continue
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes
}
