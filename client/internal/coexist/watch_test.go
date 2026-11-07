package coexist

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/instance"
)

// fakeAdapters stands in for the operating system's adapter list, which the
// test changes the way a second installation connecting would.
type fakeAdapters struct {
	mu       sync.Mutex
	adapters []Adapter
	err      error
	calls    int
}

func (f *fakeAdapters) set(adapters []Adapter, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.adapters, f.err = adapters, err
}

func (f *fakeAdapters) list() ([]Adapter, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.adapters, f.err
}

func (f *fakeAdapters) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type watchResult struct {
	conflict OverlayConflict
	ok       bool
}

func startWatch(ctx context.Context, changes <-chan struct{}, f *fakeAdapters) <-chan watchResult {
	out := make(chan watchResult, 1)
	go func() {
		c, ok := watchOverlay(ctx, changes, time.Millisecond, []netip.Prefix{pfx("100.80.0.0/16")}, f.list)
		out <- watchResult{c, ok}
	}()
	return out
}

// SBS-COEX-04: the primary connects after the secondary with an overlapping
// overlay. The secondary is told on the next address change.
func TestWatchOverlayReportsLateConflict(t *testing.T) {
	f := &fakeAdapters{adapters: []Adapter{{Name: "wt0", Prefixes: []netip.Prefix{pfx("10.20.0.0/16")}}}}
	changes := make(chan struct{}, 1)
	done := startWatch(context.Background(), changes, f)

	require.Eventually(t, func() bool { return f.callCount() >= 1 }, time.Second, time.Millisecond, "initial check")
	select {
	case r := <-done:
		t.Fatalf("returned without a conflict: %+v", r)
	default:
	}

	f.set([]Adapter{{Name: "wt0", Prefixes: []netip.Prefix{pfx("100.80.0.0/16")}}}, nil)
	changes <- struct{}{}

	select {
	case r := <-done:
		require.True(t, r.ok, "conflict found")
		assert.Equal(t, OverlayConflict{Adapter: "wt0", Own: pfx("100.80.0.0/16"), Other: pfx("100.80.0.0/16")},
			r.conflict, "conflict")
	case <-time.After(5 * time.Second):
		t.Fatal("the late conflict was not reported")
	}
}

// An overlap that exists before the watch starts is reported by the first check,
// without waiting for a change.
func TestWatchOverlayChecksAtStart(t *testing.T) {
	f := &fakeAdapters{adapters: []Adapter{{Name: "wt_other", Prefixes: []netip.Prefix{pfx("100.80.7.1/16")}}}}
	select {
	case r := <-startWatch(context.Background(), nil, f):
		assert.True(t, r.ok, "conflict found")
		assert.Equal(t, "wt_other", r.conflict.Adapter, "adapter")
	case <-time.After(5 * time.Second):
		t.Fatal("the existing conflict was not reported")
	}
}

// A failed listing keeps the tunnel up and the watch running; the next change
// checks again.
func TestWatchOverlayKeepsWatchingAfterListError(t *testing.T) {
	f := &fakeAdapters{err: errors.New("listing failed")}
	changes := make(chan struct{}, 1)
	done := startWatch(context.Background(), changes, f)

	require.Eventually(t, func() bool { return f.callCount() >= 1 }, time.Second, time.Millisecond, "initial check")
	f.set([]Adapter{{Name: "wt0", Prefixes: []netip.Prefix{pfx("100.80.0.0/24")}}}, nil)
	changes <- struct{}{}

	select {
	case r := <-done:
		assert.True(t, r.ok, "conflict found after the error")
	case <-time.After(5 * time.Second):
		t.Fatal("the watch stopped after a listing error")
	}
}

func TestWatchOverlayEndsWithContext(t *testing.T) {
	f := &fakeAdapters{}
	ctx, cancel := context.WithCancel(context.Background())
	done := startWatch(ctx, make(chan struct{}), f)
	require.Eventually(t, func() bool { return f.callCount() >= 1 }, time.Second, time.Millisecond, "initial check")
	cancel()

	select {
	case r := <-done:
		assert.False(t, r.ok, "no conflict when the context ends")
	case <-time.After(5 * time.Second):
		t.Fatal("the watch did not end with its context")
	}
}

func TestWatchOverlayIgnoresPrimary(t *testing.T) {
	primary, err := instance.ForPlatform("windows", "acme")
	require.NoError(t, err)
	addr := wgaddr.Address{IP: netip.MustParseAddr("10.20.0.5"), Network: pfx("10.20.0.0/16")}

	_, ok := WatchOverlay(context.Background(), primary.WithRole(instance.RolePrimary), "wt_acme", addr)
	assert.False(t, ok, "a primary is not watched")
	_, ok = WatchOverlay(context.Background(), instance.Default(), "wt0", addr)
	assert.False(t, ok, "the default installation is not watched")
}
