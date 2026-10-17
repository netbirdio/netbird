//go:build !android

package iptables

import (
	"sync"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

// ipsetSupport tracks whether ipset-backed firewall rules can be installed.
//
// It starts optimistic and latches to unsupported once the kernel has proven
// otherwise: either the hash:net set type is missing (ip_set_hash_net) or
// iptables cannot match against a set (xt_set). Callers then emit per-prefix
// rules instead. Without the fallback, a rule referencing an unusable set is
// never installed and the catch-all DROP silently blocks traffic the policy
// permits.
//
// One instance is shared by the families of both address families, because
// ipset availability is a property of the kernel rather than of any single
// table.
type ipsetSupport struct {
	mu          sync.RWMutex
	unsupported bool
}

func newIPSetSupport() *ipsetSupport {
	return &ipsetSupport{}
}

func (s *ipsetSupport) supported() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return !s.unsupported
}

// markUnsupported records that ipset cannot be used, logging the reason once.
func (s *ipsetSupport) markUnsupported(cause error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.unsupported {
		return
	}
	s.unsupported = true

	log.Warnf("ipset is unavailable (%v); falling back to per-prefix firewall rules. "+
		"Ensure the kernel provides ip_set_hash_net and xt_set; without them rule "+
		"sets are larger and slower to converge on networks with many peers", cause)
}

// ipsetUsable reports whether the kernel can create a hash:net set and match it
// from an iptables rule in the given chain. It confirms a suspected ipset
// failure before the capability is latched off: a rule can fail for reasons
// that say nothing about the kernel's ipset support (a set name already taken
// by an incompatible type, a transient xtables lock), and latching on one of
// those would drop set matching for the rest of the process lifetime, including
// for the dynamic destination sets that have no per-prefix form.
func (r *family) ipsetUsable(chain string) bool {
	// A short unique name so concurrent processes don't collide and we only
	// ever destroy the set we created ourselves. ipset names are limited to
	// 31 characters.
	name := "nb-probe-" + uuid.New().String()[:8]

	if err := r.createIPSet(name); err != nil {
		log.Debugf("ipset probe: create %s: %v", name, err)
		return false
	}
	defer func() {
		if err := r.destroyIPSet(name); err != nil {
			log.Debugf("ipset probe: destroy %s: %v", name, err)
		}
	}()

	// Match-only rule with no target: the set is empty, so while it is
	// installed it matches nothing and reaches no verdict.
	specs := []string{"-m", "set", matchSet, name, "src"}
	if err := r.iptablesClient.Insert(tableFilter, chain, 1, specs...); err != nil {
		log.Debugf("ipset probe: match a set from %s: %v", chain, err)
		return false
	}

	if err := r.iptablesClient.DeleteIfExists(tableFilter, chain, specs...); err != nil {
		log.Errorf("remove ipset probe rule from %s: %v", chain, err)
	}

	return true
}

// ipsetUnusableError marks a failure attributable to ipset, so the caller can
// retry the same rule in its per-prefix form before latching the capability off.
type ipsetUnusableError struct {
	cause error
}

func (e *ipsetUnusableError) Error() string { return e.cause.Error() }

func (e *ipsetUnusableError) Unwrap() error { return e.cause }

func ipsetUnusable(cause error) error {
	return &ipsetUnusableError{cause: cause}
}
