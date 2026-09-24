package configurer

import (
	"net"
	"net/netip"
	"slices"
	"sync"
)

type peerKey string

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
// An operator reconfiguring the device out of band, through `wg set` or the UAPI socket, is
// the one way the mirror can still go stale; callers fall back to the device when a peer is
// missing from it, which also reseats ownership of that peer's prefixes.
type allowedIPStore struct {
	mu     sync.RWMutex
	peers  map[peerKey][]netip.Prefix
	owners map[netip.Prefix]peerKey
}

func newAllowedIPStore() *allowedIPStore {
	return &allowedIPStore{
		peers:  make(map[peerKey][]netip.Prefix),
		owners: make(map[netip.Prefix]peerKey),
	}
}

// get returns the prefixes recorded for a peer, and whether the peer is known at all.
// The caller receives a copy and may retain or modify it freely.
func (s *allowedIPStore) get(key string) ([]netip.Prefix, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	prefixes, ok := s.peers[peerKey(key)]
	if !ok {
		return nil, false
	}
	return slices.Clone(prefixes), true
}

// set replaces the prefixes recorded for a peer.
func (s *allowedIPStore) set(key string, prefixes []netip.Prefix) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := peerKey(key)
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
func (s *allowedIPStore) add(key string, prefixes []netip.Prefix) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.mergeLocked(peerKey(key), prefixes)
}

// addExisting is add for an update-only device operation. Such an operation is a silent
// no-op when the peer is absent, so recording a peer here would leave the store claiming
// prefixes the device never took, and the peer would then be recreated by the next endpoint
// removal, stealing those allowed IPs from the peer that legitimately holds them.
func (s *allowedIPStore) addExisting(key string, prefixes []netip.Prefix) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := peerKey(key)
	if _, ok := s.peers[k]; !ok {
		return
	}
	s.mergeLocked(k, prefixes)
}

// forget drops every prefix recorded for a peer.
func (s *allowedIPStore) forget(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := peerKey(key)
	s.releaseLocked(k)
	delete(s.peers, k)
}

// reset drops every peer, mirroring a device reconfiguration that replaces the peer set.
func (s *allowedIPStore) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.peers = make(map[peerKey][]netip.Prefix)
	s.owners = make(map[netip.Prefix]peerKey)
}

func (s *allowedIPStore) mergeLocked(k peerKey, prefixes []netip.Prefix) {
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
func (s *allowedIPStore) claimLocked(k peerKey, prefix netip.Prefix) {
	if owner, ok := s.owners[prefix]; ok && owner != k {
		s.peers[owner] = slices.DeleteFunc(s.peers[owner], func(p netip.Prefix) bool {
			return p == prefix
		})
	}
	s.owners[prefix] = k
}

// releaseLocked drops a peer's claim on every prefix it currently holds.
func (s *allowedIPStore) releaseLocked(k peerKey) {
	for _, prefix := range s.peers[k] {
		if s.owners[prefix] == k {
			delete(s.owners, prefix)
		}
	}
}

// normalizePrefix puts a prefix into the form the store recognises it by. It clears the
// host bits, which a device does on its own, so a caller passing 10.20.0.1/16 still matches
// the 10.20.0.0/16 read back from the device; and it unmaps a v4-mapped prefix so that it
// compares equal to, and marshals like, the plain v4 prefix for the same network.
//
// Masking comes first because it also decides the address family: only a prefix at least 96
// bits long keeps the mapped marker through the mask, so a shorter prefix inside the mapped
// range is a genuine v6 prefix and unmapping it would yield an invalid v4 prefix.
func normalizePrefix(prefix netip.Prefix) netip.Prefix {
	masked := prefix.Masked()

	addr := masked.Addr()
	if !addr.Is4In6() {
		return masked
	}
	return netip.PrefixFrom(addr.Unmap(), masked.Bits()-96)
}

func normalizePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	normalized := make([]netip.Prefix, len(prefixes))
	for i, prefix := range prefixes {
		normalized[i] = normalizePrefix(prefix)
	}
	return normalized
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
