package mdm

import (
	"context"
	"reflect"
	"sort"
	"time"

	log "github.com/sirupsen/logrus"
)

// DefaultReloadInterval is the production cadence at which the desktop daemon
// re-reads the OS-native MDM policy. Picked to balance responsiveness against
// registry/plist I/O overhead. Mobile builds use OS-side notifications
// instead, hence anticipating the ticker mechanism entirely.
const DefaultReloadInterval = 1 * time.Minute

// policyLoader is the indirection through which the ticker reads the
// OS-native policy, both for the initial observation and on every tick.
// Production points it at LoadPolicy; tests in this package override it to
// feed a scripted sequence of policies without touching the real OS store.
var policyLoader = LoadPolicy

// Ticker periodically re-reads the OS-native MDM policy via LoadPolicy and
// invokes the onChange callback (supplied to Run) whenever the observed
// Policy diverges from the last observation (added / removed / changed
// keys). Launch with Run from a goroutine; cancel the supplied context
// to stop.
type Ticker struct {
	interval time.Duration
	prev     *Policy
}

// NewTicker constructs a Ticker that will re-read the OS-native policy
// every reloadInterval once Run is called.
// The initial snapshot is populated by calling policyLoader at
// construction time so the first tick only fires
// onChange when the policy actually changed since boot — without
// this baseline the first tick would report every currently-managed
// key as "added" and trigger a spurious engine restart.
func NewTicker(reloadInterval time.Duration) *Ticker {
	return &Ticker{
		interval: reloadInterval,
		prev:     policyLoader(),
	}
}

// Run blocks until ctx is cancelled, polling the OS-native policy store at
// the configured cadence and emitting log lines + onChange callback on
// every observed diff. onChange must be non-nil.
func (t *Ticker) Run(ctx context.Context, onChange func(prev, curr *Policy) error) {
	tk := time.NewTicker(t.interval)
	defer tk.Stop()
	log.Infof("MDM policy reload ticker started (interval=%s)", t.interval)
	for {
		select {
		case <-ctx.Done():
			log.Info("MDM policy reload ticker stopped")
			return
		case <-tk.C:
			curr := policyLoader()
			if policiesEqual(t.prev, curr) {
				continue
			}
			added, removed, changed := diffPolicies(t.prev, curr)
			log.Infof("MDM policy changed: added=%v removed=%v changed=%v",
				added, removed, changed)
			prev := t.prev
			if err := onChange(prev, curr); err != nil {
				log.Errorf("MDM policy change handler failed (retrying in 1 minute): %v", err)
				continue
			}
			t.prev = curr
		}
	}
}

// policiesEqual reports whether two Policy instances carry the same
// managed key set with identical values. Nil and empty policies
// compare equal; one-nil/one-non-empty compare not equal; otherwise
// the underlying values maps are compared with reflect.DeepEqual.
func policiesEqual(a, b *Policy) bool {
	if a.IsEmpty() && b.IsEmpty() {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return reflect.DeepEqual(a.values, b.values)
}

// diffPolicies returns the keys added in curr, removed from prev, and
// whose values changed between prev and curr. Each slice is sorted
// lexicographically for stable log output; value differences are
// determined with reflect.DeepEqual.
func diffPolicies(prev, curr *Policy) (added, removed, changed []string) {
	prevKVs := mapOf(prev)
	currKVs := mapOf(curr)
	for k := range currKVs {
		if _, ok := prevKVs[k]; !ok {
			added = append(added, k)
		} else if !reflect.DeepEqual(prevKVs[k], currKVs[k]) {
			changed = append(changed, k)
		}
	}
	for k := range prevKVs {
		if _, ok := currKVs[k]; !ok {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(changed)
	return added, removed, changed
}

// mapOf returns a (possibly empty, never nil) copy of the underlying
// values map of a Policy so callers outside this package can compare
// keys/values across the type boundary. Returns an empty map on nil p.
func mapOf(p *Policy) map[string]any {
	if p == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(p.values))
	for k, v := range p.values {
		out[k] = v
	}
	return out
}
