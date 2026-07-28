package refcounter

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"

	"github.com/hashicorp/go-multierror"

	nberrors "github.com/netbirdio/netbird/client/errors"
)

// allowedIPsEntry holds the per-peer reference counts for a single prefix and which peer is
// currently installed in WireGuard. WireGuard allows a prefix on exactly one peer, so at most
// one peer is active at a time even when several peers reference the prefix.
type allowedIPsEntry struct {
	// peers maps a peerKey to the number of references holding the prefix for that peer.
	peers map[string]int
	// active is the peerKey currently installed in WireGuard for this prefix ("" if none).
	active string
	// total is the sum of all per-peer reference counts (kept in sync with peers).
	total int
}

// AllowedIPsRefCounter is a peer-aware reference counter for WireGuard AllowedIPs.
//
// The generic Counter keys only by prefix and remembers a single Out value set by the first
// caller, which it never changes. That is wrong for AllowedIPs: two independent watchers (or
// multiple resolved domains) can reference the same prefix through different peers, and when the
// peer currently installed in WireGuard releases its last reference the prefix must be handed over
// to a surviving peer instead of being left pointing at the released one.
//
// It calls add/remove (which program WireGuard) only on the transitions that matter:
//   - add on the first reference for a prefix, or when swapping the active peer;
//   - remove on the last reference for a prefix, or on the old peer during a swap.
type AllowedIPsRefCounter struct {
	mu      sync.Mutex
	entries map[netip.Prefix]*allowedIPsEntry
	add     AddFunc[netip.Prefix, string, string]
	remove  RemoveFunc[netip.Prefix, string]
}

// NewAllowedIPs creates a new peer-aware AllowedIPs reference counter.
// add programs a prefix on a peer in WireGuard and returns the peerKey to store as the active peer.
// remove unprograms the prefix from the given peer.
func NewAllowedIPs(add AddFunc[netip.Prefix, string, string], remove RemoveFunc[netip.Prefix, string]) *AllowedIPsRefCounter {
	return &AllowedIPsRefCounter{
		entries: map[netip.Prefix]*allowedIPsEntry{},
		add:     add,
		remove:  remove,
	}
}

// Increment adds a reference to prefix for peerKey. WireGuard is programmed only for the first
// reference to a prefix; while a different peer is already installed the prefix is left with it
// (first peer wins, HA at the WireGuard layer is not possible) and only the reference count is kept.
func (rm *AllowedIPsRefCounter) Increment(prefix netip.Prefix, peerKey string) (Ref[string], error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	e, ok := rm.entries[prefix]
	if !ok {
		e = &allowedIPsEntry{peers: map[string]int{}}
		rm.entries[prefix] = e
	}

	logCallerF("Increasing allowed IP ref count for prefix %v peer %s [peer %d -> %d, total %d -> %d, active %q]",
		prefix, peerKey, e.peers[peerKey], e.peers[peerKey]+1, e.total, e.total+1, e.active)

	// Program WireGuard only when nothing is installed yet for this prefix.
	if e.active == "" {
		out, err := rm.add(prefix, peerKey)
		if errors.Is(err, ErrIgnore) {
			if e.total == 0 {
				delete(rm.entries, prefix)
			}
			return Ref[string]{Count: e.total, Out: e.active}, nil
		}
		if err != nil {
			if e.total == 0 {
				delete(rm.entries, prefix)
			}
			return Ref[string]{}, fmt.Errorf("failed to add allowed IP %v for peer %s: %w", prefix, peerKey, err)
		}
		e.active = out
	}

	e.peers[peerKey]++
	e.total++

	return Ref[string]{Count: e.total, Out: e.active}, nil
}

// Decrement removes a reference to prefix for peerKey. When the peer currently installed in
// WireGuard releases its last reference, the prefix is swapped to a surviving peer if one exists,
// otherwise it is removed from WireGuard.
func (rm *AllowedIPsRefCounter) Decrement(prefix netip.Prefix, peerKey string) (Ref[string], error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	e, ok := rm.entries[prefix]
	if !ok {
		logCallerF("No allowed IP reference found for prefix %v", prefix)
		return Ref[string]{}, nil
	}

	if e.peers[peerKey] > 0 {
		logCallerF("Decreasing allowed IP ref count for prefix %v peer %s [peer %d -> %d, total %d -> %d, active %q]",
			prefix, peerKey, e.peers[peerKey], e.peers[peerKey]-1, e.total, e.total-1, e.active)
		e.peers[peerKey]--
		e.total--
		if e.peers[peerKey] == 0 {
			delete(e.peers, peerKey)
		}
	} else {
		logCallerF("No allowed IP reference found for prefix %v peer %s", prefix, peerKey)
	}

	// If the peer currently installed in WireGuard still holds references, nothing to reprogram.
	// Keying the check on the active peer (not the one just released) makes this self-healing:
	// a prior swap whose remove/add failed leaves e.active pointing at a peer with no references,
	// and this retries the hand-off on the next Decrement instead of getting stuck.
	if e.active != "" && e.peers[e.active] > 0 {
		return Ref[string]{Count: e.total, Out: e.active}, nil
	}

	// Detach the stale/gone active peer from WireGuard before reprogramming.
	if e.active != "" {
		if err := rm.remove(prefix, e.active); err != nil {
			return Ref[string]{Count: e.total, Out: e.active}, fmt.Errorf("remove allowed IP %v for peer %s: %w", prefix, e.active, err)
		}
		e.active = ""
	}

	// Hand the prefix over to a surviving peer, or drop the entry when none remain.
	if survivor, ok := pickSurvivor(e.peers); ok {
		out, err := rm.add(prefix, survivor)
		if err != nil {
			return Ref[string]{Count: e.total, Out: ""}, fmt.Errorf("swap allowed IP %v to peer %s: %w", prefix, survivor, err)
		}
		e.active = out
		return Ref[string]{Count: e.total, Out: e.active}, nil
	}

	delete(rm.entries, prefix)
	return Ref[string]{Count: 0, Out: ""}, nil
}

// Flush removes all prefixes from WireGuard and clears the counter.
func (rm *AllowedIPsRefCounter) Flush() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	var merr *multierror.Error
	for prefix, e := range rm.entries {
		if e.active == "" {
			continue
		}
		logCallerF("Flushing allowed IP for prefix %v peer %s", prefix, e.active)
		if err := rm.remove(prefix, e.active); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove allowed IP %v for peer %s: %w", prefix, e.active, err))
		}
	}

	clear(rm.entries)

	return nberrors.FormatErrorOrNil(merr)
}

// pickSurvivor deterministically selects a peer still referencing the prefix. WireGuard cannot do
// multipath for a single prefix, so any surviving peer is a valid winner; the choice is made stable
// (lowest peerKey) for predictable behavior and testability.
func pickSurvivor(peers map[string]int) (string, bool) {
	if len(peers) == 0 {
		return "", false
	}
	keys := make([]string, 0, len(peers))
	for k := range peers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys[0], true
}
