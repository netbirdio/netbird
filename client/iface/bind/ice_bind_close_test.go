package bind

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	wgConn "golang.zx2c4.com/wireguard/conn"
)

// startReceivers runs every receive function the way wireguard-go's device
// does: one goroutine per function, all tracked by a single WaitGroup. After
// calling Bind.Close, closeBindLocked waits on exactly that WaitGroup while
// holding device.net, so a receive function that never returns wedges the
// device and every goroutine that needs the same lock.
func startReceivers(fns []wgConn.ReceiveFunc) *sync.WaitGroup {
	wg, _ := startReceiversEntered(fns)
	return wg
}

// startReceiversEntered also returns a channel closed once every receive
// function has been called at least once. A receive function that has been
// entered is either inside its blocking receive or about to be, which is a
// stronger signal to synchronise on than a bare sleep.
func startReceiversEntered(fns []wgConn.ReceiveFunc) (*sync.WaitGroup, <-chan struct{}) {
	var wg sync.WaitGroup
	var entered sync.WaitGroup
	wg.Add(len(fns))
	entered.Add(len(fns))

	for i := range fns {
		go func(fn wgConn.ReceiveFunc) {
			defer wg.Done()
			buffs := [][]byte{make([]byte, 1500)}
			sizes := make([]int, 1)
			eps := make([]wgConn.Endpoint, 1)
			first := true
			for {
				if first {
					entered.Done()
					first = false
				}
				if _, err := fn(buffs, sizes, eps); err != nil {
					return
				}
			}
		}(fns[i])
	}

	allEntered := make(chan struct{})
	go func() {
		entered.Wait()
		close(allEntered)
	}()
	return &wg, allEntered
}

// closeBounded runs Close off the caller's goroutine so a regression that
// wedges it fails the test instead of hanging teardown, and reports whether it
// returned in time.
func closeBounded(iceBind *ICEBind, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		_ = iceBind.Close()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// isClosed reports whether the bind's current generation channel is closed.
func isClosed(iceBind *ICEBind) bool {
	iceBind.closedChanMu.RLock()
	ch := iceBind.closedChan
	iceBind.closedChanMu.RUnlock()
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// receiversStopped reports whether every receive function returned before the
// timeout, mirroring device.net.stopping.Wait() inside closeBindLocked.
func receiversStopped(wg *sync.WaitGroup, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// TestICEBindCloseReleasesReceivers covers the contract closeBindLocked relies
// on: once Close returns, every receive function handed out by Open must stop.
func TestICEBindCloseReleasesReceivers(t *testing.T) {
	iceBind := setupICEBind(t)

	fns, _, err := iceBind.Open(0)
	require.NoError(t, err, "opening the bind must succeed")

	wg := startReceivers(fns)
	require.NoError(t, iceBind.Close())

	require.True(t, receiversStopped(wg, 5*time.Second),
		"every receive function must return once Close returns")
}

// TestICEBindOpenDoesNotBlockOnParkedReceiver reproduces the deadlock that
// wedges interface creation.
//
// receiveRelayed used to hold closedChanMu for the whole of its blocking
// select, so a parked receiver kept the read lock indefinitely. Open takes the
// same mutex for writing to install a fresh closedChan, so it could never
// acquire it while a receiver was parked. wireguard-go reaches Open from
// Device.IpcSet and Device.Up with device.net held, so the stall takes the
// device's lock with it and every other device goroutine queues behind it.
//
// Failing here means Open never returned.
func TestICEBindOpenDoesNotBlockOnParkedReceiver(t *testing.T) {
	iceBind := setupICEBind(t)

	fns, _, err := iceBind.Open(0)
	require.NoError(t, err, "the first Open must succeed")

	wg, entered := startReceiversEntered(fns)
	t.Cleanup(func() {
		// Both bounded: a regression that wedges Close must surface as the
		// assertion below, not as a hung teardown.
		if !closeBounded(iceBind, 5*time.Second) {
			t.Error("Close did not return during teardown; the bind lifecycle is wedged even though the assertion above passed")
		}
		if !receiversStopped(wg, 5*time.Second) {
			t.Error("receive functions were still running after teardown Close, which is what closeBindLocked blocks on")
		}
	})

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("receive functions never started")
	}
	// Entered is not yet parked, so still allow the blocking receive to be
	// reached. Parking takes microseconds; this margin is six orders larger.
	time.Sleep(500 * time.Millisecond)

	reopened := make(chan struct{})
	go func() {
		// The error is irrelevant; StdNetBind rejects a second Open. What
		// matters is that the call returns at all.
		_, _, _ = iceBind.Open(0)
		close(reopened)
	}()

	select {
	case <-reopened:
	case <-time.After(10 * time.Second):
		t.Fatal("Open blocked while a receive function was parked; wireguard-go makes this call with device.net held, which is what stalls interface creation")
	}
}

// TestICEBindConcurrentOpenClose exercises Open and Close from separate
// goroutines, the way Device.IpcSet and Device.Up reach the bind, and is meant
// to be run under -race.
//
// closed and closedChan must be updated together. When they were not, Close
// could observe a stale closed and either skip close(closedChan) and
// StdNetBind.Close entirely, leaving the receive functions running, or race a
// second Close and close the same channel twice.
//
// Receive functions are deliberately not started here: this test is about the
// shared state, and parking them would turn a race report into a hang.
func TestICEBindConcurrentOpenClose(t *testing.T) {
	iceBind := setupICEBind(t)

	var wg sync.WaitGroup
	wg.Add(2)

	// Release both loops together so the calls genuinely interleave rather
	// than depending on goroutine start order.
	start := make(chan struct{})

	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 200; i++ {
			_, _, _ = iceBind.Open(0)
		}
	}()
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 200; i++ {
			_ = iceBind.Close()
		}
	}()

	close(start)
	wg.Wait()
	require.NoError(t, iceBind.Close())
	require.True(t, isClosed(iceBind), "the final Close must leave the current generation channel closed")
}

// TestICEBindCloseReleasesReceiversUnderConcurrentClose runs full Open, receive,
// Close cycles with a second Close and an Open racing the first Close. Any
// iteration where the receive functions outlive Close, or where the surviving
// generation channel is left open, is the state closeBindLocked deadlocks on.
func TestICEBindCloseReleasesReceiversUnderConcurrentClose(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test")
	}

	for i := 0; i < 200; i++ {
		iceBind := setupICEBind(t)

		fns, _, err := iceBind.Open(0)
		require.NoError(t, err, "iteration %d: opening the bind must succeed", i)
		wg := startReceivers(fns)

		start := make(chan struct{})
		var racers sync.WaitGroup
		racers.Add(3)
		for c := 0; c < 2; c++ {
			go func() {
				defer racers.Done()
				<-start
				_ = iceBind.Close()
			}()
		}
		// An Open overlapping the Closes is what produces a generation whose
		// channel outlives the flag saying the bind is closed.
		go func() {
			defer racers.Done()
			<-start
			_, _, _ = iceBind.Open(0)
		}()
		close(start)
		racers.Wait()

		// Settle on a closed bind whatever order the racers landed in.
		_ = iceBind.Close()

		if !receiversStopped(wg, 5*time.Second) {
			t.Fatalf("iteration %d: receive functions still running after Close; closeBindLocked would block here on device.net.stopping.Wait", i)
		}
		if !isClosed(iceBind) {
			t.Fatalf("iteration %d: Close returned with the current generation channel still open, so nothing will ever release its receivers", i)
		}
	}
}
