package guard

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer/ice"
)

func newTestGuard(status connStatusFunc) *Guard {
	srw := NewSRWatcher(nil, nil, nil, ice.Config{})
	return NewGuard(log.WithField("test", "guard"), status, 50*time.Millisecond, srw)
}

// countBackoffTickerGoroutines returns how many goroutines are currently sitting
// in backoff/v4.(*Ticker).run (a ticker goroutine that has not exited).
func countBackoffTickerGoroutines() int {
	buf := make([]byte, 1<<25) // 32MB
	n := runtime.Stack(buf, true)
	return strings.Count(string(buf[:n]), "backoff/v4.(*Ticker).run")
}

// TestGuard_ReconnectTicker_NoGoroutineLeakOnShutdown reproduces a observed
// leak: after a shutdown burst, ticker run/send goroutines stay parked
// forever even though every reconnect loop has exited.
func TestGuard_ReconnectTicker_NoGoroutineLeakOnShutdown(t *testing.T) {
	before := countBackoffTickerGoroutines()

	const peers = 6000
	cancels := make([]context.CancelFunc, 0, peers)
	var wg sync.WaitGroup

	// A status check slower than the tick cadence. This models the real
	// isConnectedOnAllWay/callback doing work: while the loop is busy in the
	// handler, the ticker fires the next tick and parks in send(), because
	// send() never selects on ctx.
	slowStatus := func() ConnStatus {
		time.Sleep(70 * time.Millisecond)
		return ConnStatusConnected
	}

	for range peers {
		g := newTestGuard(slowStatus)
		ctx, cancel := context.WithCancel(context.Background())
		cancels = append(cancels, cancel)
		wg.Add(1)
		go func() {
			defer wg.Done()
			g.Start(ctx, func() {})
		}()
		// Force the live ticker to be a newReconnectTicker.
		g.SetRelayedConnDisconnected()
	}

	// Let the replacement tickers get past their 800ms initial interval, so
	// many are parked in send() waiting on the (slow) consumer when we tear
	// everything down.
	time.Sleep(1500 * time.Millisecond)

	// Shutdown burst: cancel every peer at once, like engine teardown.
	for _, c := range cancels {
		c()
	}

	// Every reconnect loop must return
	waitCh := make(chan struct{})
	go func() { wg.Wait(); close(waitCh) }()
	select {
	case <-waitCh:
	case <-time.After(30 * time.Second):
		t.Fatal("not all reconnect loops returned after ctx cancel")
	}

	// Give any correctly-stopped ticker goroutines time to unwind.
	for range 50 {
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}

	leaked := countBackoffTickerGoroutines() - before
	t.Logf("backoff Ticker.run goroutines still parked after teardown of %d peers: %d", peers, leaked)
	if leaked > 0 {
		t.Errorf("LEAK: %d backoff ticker goroutines parked after all reconnect loops exited "+
			"(defer ticker.Stop() stops the initial ticker, not the live replacement)", leaked)
	}
}
