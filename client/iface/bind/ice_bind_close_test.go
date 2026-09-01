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
// It passes today and is here so a fix cannot regress the ordinary path.
func TestICEBindCloseReleasesReceivers(t *testing.T) {
	iceBind := setupICEBind(t)

	fns, _, err := iceBind.Open(0)
	require.NoError(t, err, "opening the bind must succeed")

	wg := startReceivers(fns)
	require.NoError(t, iceBind.Close())

	require.True(t, receiversStopped(wg, 5*time.Second),
		"every receive function must return once Close returns")
}

// TestICEBindConcurrentOpenClose reproduces the root cause of the interface
// creation deadlock, and fails under -race today.
//
// Open writes s.closed and Close reads it with no synchronisation, while
// closedChan is guarded by closedChanMu. The two can therefore disagree: if
// Close observes closed as false and flips it to true while Open is midway
// through installing a fresh closedChan, the bind ends up marked closed with a
// live channel and live receive functions. Every later Close then takes its
// early return, so neither close(closedChan) nor StdNetBind.Close ever runs and
// the receive functions never stop.
//
// That is what wedges closeBindLocked on device.net.stopping.Wait() during
// Device.IpcSet, holding device.net and stalling interface creation.
//
// Receive functions are deliberately not started here: this test is about the
// unsynchronised state, and parking them would turn a race report into a hang.
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

// TestICEBindCloseReleasesReceiversUnderConcurrentClose drives the consequence
// of that race: full Open, run receivers, Close cycles with a second Close
// racing the first. Any iteration where the receive functions outlive Close is
// the deadlock closeBindLocked hits.
//
// This one is probabilistic. It is the shape of the production failure rather
// than a guaranteed trigger, so treat a pass as inconclusive and a failure as
// real.
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
