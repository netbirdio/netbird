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
// device dump just to recover prefixes the process already configured itself. An operator
// reconfiguring the device out of band, through `wg set` or the UAPI socket, is the one way
// the mirror can go stale; callers fall back to the device when a peer is missing from it.
type allowedIPStore struct {
	mu    sync.RWMutex
	peers map[peerKey][]netip.Prefix
}

func newAllowedIPStore() *allowedIPStore {
	return &allowedIPStore{peers: make(map[peerKey][]netip.Prefix)}
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

	s.peers[peerKey(key)] = normalizePrefixes(prefixes)
}

// add records prefixes on a peer without dropping the ones already there, matching the
// union semantics of a peer update that does not replace its allowed IPs.
func (s *allowedIPStore) add(key string, prefixes []netip.Prefix) {
	s.mu.Lock()
	defer s.mu.Unlock()

	merged := s.peers[peerKey(key)]
	for _, prefix := range prefixes {
		prefix = normalizePrefix(prefix)
		if !slices.Contains(merged, prefix) {
			merged = append(merged, prefix)
		}
	}
	s.peers[peerKey(key)] = merged
}

// forget drops every prefix recorded for a peer.
func (s *allowedIPStore) forget(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.peers, peerKey(key))
}

// reset drops every peer, mirroring a device reconfiguration that replaces the peer set.
func (s *allowedIPStore) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.peers = make(map[peerKey][]netip.Prefix)
}

// normalizePrefix unmaps a v4-mapped v6 prefix so that it compares equal to, and marshals
// like, the plain v4 prefix for the same network. The store recognises a prefix by value, and
// prefixesToIPNets would otherwise pair a 16 byte address with a v4 sized mask.
func normalizePrefix(prefix netip.Prefix) netip.Prefix {
	addr := prefix.Addr()
	if !addr.Is4In6() {
		return prefix
	}

	bits := prefix.Bits()
	if bits >= 96 {
		bits -= 96
	}
	return netip.PrefixFrom(addr.Unmap(), bits)
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
		ones, _ := ipNet.Mask.Size()
		addr = addr.Unmap()
		// A device may report a v4 prefix as a v4-mapped address under a 128 bit mask.
		if addr.Is4() && ones >= 96 {
			ones -= 96
		}

		prefix := netip.PrefixFrom(addr, ones)
		if !prefix.IsValid() {
			continue
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}
