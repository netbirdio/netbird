package mdm

import (
	"context"
	"reflect"
	"sort"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

// defaultReloadInterval is the production cadence at which the desktop daemon
// re-reads the OS-native MDM policy. Picked to balance responsiveness against
// registry/plist I/O overhead. Mobile builds use OS-side notifications
// instead and bypass this ticker entirely. Unexported on purpose: callers do
// not pass it — NewTicker owns the default (see reloadInterval).
const defaultReloadInterval = 1 * time.Minute

// testReloadInterval is the cadence used under `go test` (detected via
// testing.Testing()) so the reload path is exercised in seconds rather than
// minutes. It has no effect on production builds, where testing.Testing()
// always returns false.
const testReloadInterval = 1 * time.Second

// reloadInterval returns the production cadence, or the accelerated test
// cadence when running under `go test` (detected via testing.Testing()).
// Centralising the choice here keeps the prod/test split in one place
// and out of the ticker's call sites.
func reloadInterval() time.Duration {
	if testing.Testing() {
		return testReloadInterval
	}
	return defaultReloadInterval
}

// policyLoader is the indirection through which the ticker reads the
// OS-native policy, both for the initial observation and on every tick.
// Production points it at LoadPolicy; tests in this package override it to
// feed a scripted sequence of policies without touching the real OS store.
var policyLoader = LoadPolicy

// Ticker periodically re-reads the OS-native MDM policy via LoadPolicy and
// invokes onChange whenever the observed Policy diverges from the last
// observation (added / removed / changed keys). Launch with Run from a
// goroutine; cancel the supplied context to stop.
type Ticker struct {
	interval time.Duration
	onChange func(prev, curr *Policy)
	prev     *Policy
}

// NewTicker constructs a Ticker that re-reads the OS-native policy
// every reloadInterval() and invokes onChange on any diff. The
// cadence is owned by reloadInterval (production default, accelerated
// under `go test`); callers do not supply it. onChange may be nil for
// a log-only ticker. The initial snapshot is populated by calling
// policyLoader at construction time so the first tick only fires
// onChange when the policy actually changed since boot — without
// this baseline the first tick would report every currently-managed
// key as "added" and trigger a spurious engine restart.
func NewTicker(onChange func(prev, curr *Policy)) *Ticker {
	return &Ticker{
		interval: reloadInterval(),
		onChange: onChange,
		prev:     policyLoader(),
	}
}

// Run blocks until ctx is cancelled, polling the OS-native policy store at
// the configured cadence and emitting log lines + onChange callback on
// every observed diff.
func (t *Ticker) Run(ctx context.Context) {
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
			if PoliciesEqual(t.prev, curr) {
				continue
			}
			added, removed, changed := diffPolicies(t.prev, curr)
			log.Infof("MDM policy changed: added=%v removed=%v changed=%v",
				added, removed, changed)
			prev := t.prev
			t.prev = curr
			if t.onChange != nil {
				t.onChange(prev, curr)
			}
		}
	}
}

// PoliciesEqual reports whether two Policy instances carry the same
// managed key set with identical values. Nil and empty policies
// compare equal; one-nil/one-non-empty compare not equal; otherwise
// the underlying values maps are compared with reflect.DeepEqual.
func PoliciesEqual(a, b *Policy) bool {
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
