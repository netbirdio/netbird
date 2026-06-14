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

// withPolicyLoader overrides the package-level policyLoader for the duration
// of the test so the ticker observes a scripted policy instead of the real
// OS-native store. The original loader is restored on cleanup.
func withPolicyLoader(t *testing.T, fn func() *Policy) {
	t.Helper()
	prev := policyLoader
	policyLoader = fn
	t.Cleanup(func() { policyLoader = prev })
}

func TestTicker_FiresOnChangeWithDelta(t *testing.T) {
	var mu sync.Mutex
	current := NewPolicy(nil) // initial observation: empty (no enforcement)
	withPolicyLoader(t, func() *Policy {
		mu.Lock()
		defer mu.Unlock()
		return current
	})

	type change struct{ prev, curr *Policy }
	changes := make(chan change, 1)
	tk := NewTicker(testReloadInterval)
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
	// Stop Run and wait for it to exit before returning, so the policyLoader
	// restore in t.Cleanup can't race the ticker goroutine still reading it.
	defer func() { cancel(); <-done }()

	// Flip the OS-observed policy from empty to one managed key. The next
	// tick must detect the diff and invoke onChange.
	mu.Lock()
	current = NewPolicy(map[string]any{KeyManagementURL: "https://mdm.example.com:443"})
	mu.Unlock()

	select {
	case c := <-changes:
		assert.True(t, c.prev.IsEmpty(), "prev should be the initial empty policy")
		assert.True(t, c.curr.HasKey(KeyManagementURL), "curr should carry the newly-pushed managed key")
	case <-time.After(5 * time.Second):
		t.Fatal("onChange not invoked within 5s; ticker should fire every 1s under test")
	}
}

func TestTicker_NoCallbackWhenPolicyUnchanged(t *testing.T) {
	withPolicyLoader(t, func() *Policy {
		return NewPolicy(map[string]any{KeyBlockInbound: true})
	})

	fired := make(chan struct{}, 1)
	tk := NewTicker(testReloadInterval)

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

	// Over ~2 ticks at the 1s test cadence the policy never changes, so the
	// diff guard must suppress the callback entirely.
	select {
	case <-fired:
		t.Fatal("onChange fired despite an unchanged policy")
	case <-time.After(2500 * time.Millisecond):
	}
}
