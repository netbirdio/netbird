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
	var wg sync.WaitGroup
	wg.Add(len(fns))
	for i := range fns {
		go func(fn wgConn.ReceiveFunc) {
			defer wg.Done()
			buffs := [][]byte{make([]byte, 1500)}
			sizes := make([]int, 1)
			eps := make([]wgConn.Endpoint, 1)
			for {
				if _, err := fn(buffs, sizes, eps); err != nil {
					return
				}
			}
		}(fns[i])
	}
	return &wg
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

	wg := startReceivers(fns)
	t.Cleanup(func() {
		_ = iceBind.Close()
		// Bounded so a regression reports the assertion below rather than
		// hanging the whole package until the go test timeout.
		receiversStopped(wg, 5*time.Second)
	})

	// Let receiveRelayed reach its blocking select before reopening.
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

	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_, _, _ = iceBind.Open(0)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = iceBind.Close()
		}
	}()

	wg.Wait()
	require.NoError(t, iceBind.Close())
}

// TestICEBindCloseReleasesReceiversUnderConcurrentClose runs full Open, receive,
// Close cycles with a second Close racing the first. Any iteration where the
// receive functions outlive Close is the state closeBindLocked deadlocks on.
func TestICEBindCloseReleasesReceiversUnderConcurrentClose(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test")
	}

	for i := 0; i < 200; i++ {
		iceBind := setupICEBind(t)

		fns, _, err := iceBind.Open(0)
		require.NoError(t, err, "iteration %d: opening the bind must succeed", i)
		wg := startReceivers(fns)

		var closers sync.WaitGroup
		closers.Add(2)
		for c := 0; c < 2; c++ {
			go func() {
				defer closers.Done()
				_ = iceBind.Close()
			}()
		}
		closers.Wait()

		if !receiversStopped(wg, 5*time.Second) {
			t.Fatalf("iteration %d: receive functions still running after Close; closeBindLocked would block here on device.net.stopping.Wait", i)
		}
	}
}
