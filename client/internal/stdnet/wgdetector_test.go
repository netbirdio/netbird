package stdnet

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newCountingDetector returns a detector whose probe records how often it ran, so a test
// can assert on the thing this type exists for rather than on its return value alone.
func newCountingDetector(t *testing.T, ttl time.Duration, answer bool) (*WGDetector, *atomic.Int64) {
	t.Helper()

	var calls atomic.Int64
	d := &WGDetector{
		ttl:   ttl,
		cache: make(map[string]wgDetectorEntry),
		probe: func(string) bool {
			calls.Add(1)
			return answer
		},
	}
	return d, &calls
}

func TestWGDetectorAsksOncePerInterfaceWithinTheTTL(t *testing.T) {
	d, calls := newCountingDetector(t, time.Minute, true)

	for i := 0; i < 20; i++ {
		assert.True(t, d.IsWireGuard("wt0"), "cached answer must not change")
	}
	assert.Equal(t, int64(1), calls.Load(), "the interface must be probed once within the TTL")

	d.IsWireGuard("eth0")
	assert.Equal(t, int64(2), calls.Load(), "a different interface is a different question and is probed on its own")
}

func TestWGDetectorReprobesAfterTheTTL(t *testing.T) {
	d, calls := newCountingDetector(t, time.Millisecond, true)

	require.True(t, d.IsWireGuard("wt0"), "first answer")
	require.Equal(t, int64(1), calls.Load(), "first call probes")

	time.Sleep(5 * time.Millisecond)

	require.True(t, d.IsWireGuard("wt0"), "answer after expiry")
	assert.Equal(t, int64(2), calls.Load(), "an expired entry must be probed again")
}

func TestWGDetectorCollapsesConcurrentProbes(t *testing.T) {
	var calls atomic.Int64
	release := make(chan struct{})
	d := &WGDetector{
		ttl:   time.Minute,
		cache: make(map[string]wgDetectorEntry),
		probe: func(string) bool {
			calls.Add(1)
			<-release
			return true
		},
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.IsWireGuard("wt0")
		}()
	}

	// The sleep only lets the callers pile up on the blocked probe so the collapse is
	// exercised. The count does not depend on it: a caller that arrives after the probe
	// finished finds the fresh entry, either before or inside the singleflight group.
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()

	assert.Equal(t, int64(1), calls.Load(), "concurrent callers must share one probe")
}

func TestWGDetectorNilProbesEveryTime(t *testing.T) {
	var d *WGDetector
	// A nil detector keeps the uncached behaviour, which is what the callers that build one
	// filter for their whole lifetime rely on. It must not panic.
	assert.NotPanics(t, func() { d.IsWireGuard("definitely-not-an-interface-0") },
		"a nil detector must fall back to probing")
}

func TestInterfaceFilter(t *testing.T) {
	wgDetector, calls := newCountingDetector(t, time.Minute, true)
	plainDetector, _ := newCountingDetector(t, time.Minute, false)

	t.Run("loopback is rejected without probing", func(t *testing.T) {
		filter := InterfaceFilter(nil, wgDetector)
		assert.False(t, filter("lo"), "loopback must never be offered to ICE")
		assert.Equal(t, int64(0), calls.Load(), "a name settled by prefix must not reach the probe")
	})

	t.Run("a disallowed interface is rejected without probing", func(t *testing.T) {
		filter := InterfaceFilter([]string{"wt"}, wgDetector)
		assert.False(t, filter("wt0"), "a blacklisted interface must be rejected")
		assert.Equal(t, int64(0), calls.Load(), "a name settled by the disallow list must not reach the probe")
	})

	t.Run("an unlisted WireGuard interface is rejected", func(t *testing.T) {
		filter := InterfaceFilter(nil, wgDetector)
		assert.False(t, filter("somewg0"), "a WireGuard interface must not be used to build a tunnel")
	})

	t.Run("an ordinary interface is allowed", func(t *testing.T) {
		filter := InterfaceFilter(nil, plainDetector)
		assert.True(t, filter("eth0"), "a plain interface must remain available to ICE")
	})
}

func TestInterfaceFilterSharesOneProbeAcrossFilters(t *testing.T) {
	d, calls := newCountingDetector(t, time.Minute, false)

	// Every ICE agent builds its own filter, twice, and each one is asked about every
	// interface. Sharing the detector is what keeps that from repeating the probe.
	for i := 0; i < 10; i++ {
		filter := InterfaceFilter(nil, d)
		require.True(t, filter("eth0"), "a plain interface stays allowed")
		require.True(t, filter("eth1"), "a plain interface stays allowed")
	}

	assert.Equal(t, int64(2), calls.Load(), "one probe per interface, not per filter")
}

func TestWGDetectorDropsExpiredEntries(t *testing.T) {
	d, _ := newCountingDetector(t, time.Millisecond, false)

	for _, name := range []string{"veth1", "veth2", "veth3"} {
		d.IsWireGuard(name)
	}
	time.Sleep(5 * time.Millisecond)
	d.IsWireGuard("eth0")

	d.mu.RLock()
	defer d.mu.RUnlock()
	assert.Len(t, d.cache, 1, "expired entries of vanished interfaces must be dropped")
	assert.Contains(t, d.cache, "eth0", "the fresh answer must be kept")
}
