package mdm

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testReloadInterval for speeding up the ticker cadence under `go test`
const testReloadInterval = 1 * time.Second

// fakePolicyFetcher implements PolicyFetcher returning a scripted
// policy map. Goroutine-safe so the test can mutate the script while
// the ticker is observing it.
type fakePolicyFetcher struct {
	mu     sync.Mutex
	values map[string]any
}

func (f *fakePolicyFetcher) Fetch() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.values == nil {
		return nil
	}
	out := make(map[string]any, len(f.values))
	for k, v := range f.values {
		out[k] = v
	}
	return out
}

func (f *fakePolicyFetcher) set(values map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.values = values
}

func TestTicker_FiresOnChangeWithDelta(t *testing.T) {
	fetcher := &fakePolicyFetcher{} // initial observation: empty (no enforcement)
	loader := NewLoader(fetcher)

	type change struct{ prev, curr *Policy }
	changes := make(chan change, 1)
	tk := NewTicker(testReloadInterval, loader)
	require.Equal(t, testReloadInterval, tk.interval)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		tk.Run(ctx, func(prev, curr *Policy) error {
			select {
			case changes <- change{prev, curr}:
			default:
			}
			return nil
		})
		close(done)
	}()
	// Stop Run and wait for it to exit before returning, so the test
	// goroutine doesn't race the still-running ticker.
	defer func() { cancel(); <-done }()

	// Flip the OS-observed policy from empty to one managed key. The
	// next tick must detect the diff and invoke onChange.
	fetcher.set(map[string]any{KeyManagementURL: "https://mdm.example.com:443"})

	select {
	case c := <-changes:
		assert.True(t, c.prev.IsEmpty(), "prev should be the initial empty policy")
		assert.True(t, c.curr.HasKey(KeyManagementURL), "curr should carry the newly-pushed managed key")
	case <-time.After(5 * time.Second):
		t.Fatal("onChange not invoked within 5s; ticker should fire every 1s under test")
	}
}

func TestTicker_NoCallbackWhenPolicyUnchanged(t *testing.T) {
	fetcher := &fakePolicyFetcher{values: map[string]any{KeyBlockInbound: true}}
	loader := NewLoader(fetcher)

	fired := make(chan struct{}, 1)
	tk := NewTicker(testReloadInterval, loader)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		tk.Run(ctx, func(_, _ *Policy) error {
			select {
			case fired <- struct{}{}:
			default:
			}
			return nil
		})
		close(done)
	}()
	defer func() { cancel(); <-done }()

	// Over ~2 ticks at the 1s test cadence the policy never changes,
	// so the diff guard must suppress the callback entirely.
	select {
	case <-fired:
		t.Fatal("onChange fired despite an unchanged policy")
	case <-time.After(2500 * time.Millisecond):
	}
}
