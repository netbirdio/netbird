package server

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeProber implements both healthProbeRunner and statsRefresher with
// caller-supplied behaviour.
type fakeProber struct {
	onProbe   func() bool
	onRefresh func()
}

func (f fakeProber) RunHealthProbes(context.Context, bool) bool {
	return f.onProbe()
}

func (f fakeProber) RefreshWireGuardStats() error {
	if f.onRefresh != nil {
		f.onRefresh()
	}
	return nil
}

func TestProbeThrottle_CachesAfterSuccess(t *testing.T) {
	pt := newProbeThrottle(time.Minute)

	var probes, refreshes int
	prober := fakeProber{
		onProbe:   func() bool { probes++; return true },
		onRefresh: func() { refreshes++ },
	}

	pt.Run(context.Background(), prober, prober, false)
	pt.Run(context.Background(), prober, prober, false)

	if probes != 1 {
		t.Fatalf("expected 1 probe within the throttle window, got %d", probes)
	}
	if refreshes != 1 {
		t.Fatalf("expected the throttled caller to refresh stats once, got %d", refreshes)
	}
}

func TestProbeThrottle_StaysOpenWhileUnhealthy(t *testing.T) {
	pt := newProbeThrottle(time.Minute)

	var probes int
	prober := fakeProber{onProbe: func() bool { probes++; return false }} // never healthy

	// Sequential, non-overlapping callers must each re-probe while unhealthy:
	// a failed probe does not advance the throttle window.
	pt.Run(context.Background(), prober, prober, false)
	pt.Run(context.Background(), prober, prober, false)
	pt.Run(context.Background(), prober, prober, false)

	if probes != 3 {
		t.Fatalf("expected every non-overlapping caller to probe while unhealthy, got %d", probes)
	}
}

func TestProbeThrottle_SingleFlightSharesResult(t *testing.T) {
	pt := newProbeThrottle(time.Minute)

	var probes int32
	release := make(chan struct{})
	started := make(chan struct{})

	// First caller blocks inside the probe until released, holding the lock so
	// the others pile up behind it.
	prober := fakeProber{onProbe: func() bool {
		if atomic.AddInt32(&probes, 1) == 1 {
			close(started)
			<-release
		}
		return false // unhealthy — the share must happen regardless of result
	}}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		pt.Run(context.Background(), prober, prober, false)
	}()

	<-started // ensure the first probe is in flight before the burst arrives

	const waiters = 9
	wg.Add(waiters)
	for i := 0; i < waiters; i++ {
		go func() {
			defer wg.Done()
			pt.Run(context.Background(), prober, prober, false)
		}()
	}

	// Give the waiters time to block on the lock, then let the first finish.
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := atomic.LoadInt32(&probes); got != 1 {
		t.Fatalf("expected a concurrent burst to run exactly 1 probe, got %d", got)
	}
}
