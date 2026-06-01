package mdm

import (
	"context"
	"reflect"
	"sort"
	"time"

	log "github.com/sirupsen/logrus"
)

// DefaultReloadInterval is the cadence at which the desktop daemon re-reads
// the OS-native MDM policy. Picked to balance responsiveness against
// registry/plist I/O overhead. Mobile builds use OS-side notifications
// instead and bypass this ticker entirely.
const DefaultReloadInterval = 1 * time.Minute

// Ticker periodically re-reads the OS-native MDM policy via LoadPolicy and
// invokes onChange whenever the observed Policy diverges from the last
// observation (added / removed / changed keys). Launch with Run from a
// goroutine; cancel the supplied context to stop.
type Ticker struct {
	interval time.Duration
	onChange func(prev, curr *Policy)
	prev     *Policy
}

// NewTicker constructs a Ticker that calls LoadPolicy every `interval` and
// invokes `onChange` on any diff. Pass a zero interval to fall back to
// DefaultReloadInterval. onChange may be nil for a log-only ticker.
func NewTicker(interval time.Duration, onChange func(prev, curr *Policy)) *Ticker {
	if interval <= 0 {
		interval = DefaultReloadInterval
	}
	return &Ticker{
		interval: interval,
		onChange: onChange,
		prev:     LoadPolicy(),
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
			curr := LoadPolicy()
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

// PoliciesEqual reports whether two Policy instances carry the same managed
// key set with identical values. Nil and empty policies compare equal.
func PoliciesEqual(a, b *Policy) bool {
	if a.IsEmpty() && b.IsEmpty() {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return reflect.DeepEqual(a.values, b.values)
}

// diffPolicies returns the keys added in curr, removed from prev, and whose
// value changed. Returned slices are sorted for stable log output.
func diffPolicies(prev, curr *Policy) (added, removed, changed []string) {
	prevKeys := mapOf(prev)
	currKeys := mapOf(curr)
	for k := range currKeys {
		if _, ok := prevKeys[k]; !ok {
			added = append(added, k)
		} else if !reflect.DeepEqual(prevKeys[k], currKeys[k]) {
			changed = append(changed, k)
		}
	}
	for k := range prevKeys {
		if _, ok := currKeys[k]; !ok {
			removed = append(removed, k)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(changed)
	return added, removed, changed
}

// mapOf returns a (possibly empty, never nil) copy of the underlying values
// map of a Policy so callers outside this package can compare across the
// public Policy boundary without touching unexported state.
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
