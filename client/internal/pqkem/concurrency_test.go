package pqkem

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestConcurrency_RecoversViaResignalAfterDataPathBreak exercises the A-light recovery:
// a data-path rotation can no longer converge (OnRekeyFailed), and re-bootstrapping over
// signalling resyncs both peers on a fresh PSK — even while the data path stays broken,
// since the signal channel is independent of it.
func TestConcurrency_RecoversViaResignalAfterDataPathBreak(t *testing.T) {
	dA, dB, wgA, wgB, lbB := pair(t)
	defer dA.Stop()
	defer dB.Stop()

	// Tighten B's timings and make a single rotation miss raise OnRekeyFailed. Set
	// before any exchange loop spawns (the loop reads these fields).
	dB.retryInterval = 5 * time.Millisecond
	dB.maxRetries = 2
	dB.maxRekeyFailures = 1

	bootstrap(t, dA, dB)
	dA.OnDataPathRekeyed("bbbb", 0)
	dB.OnDataPathRekeyed("aaaa", 0)
	psk1 := wgB.psk("aaaa")
	require.NotEqual(t, PSK{}, psk1)
	require.Equal(t, psk1, wgA.psk("bbbb"), "converged on the same PSK after bootstrap+rotation")

	// Data path breaks: the rotation can no longer converge -> OnRekeyFailed.
	lbB.drop.Store(true)
	_, err := dB.startExchangeTest("aaaa", false, ExchangeID{})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return failedCount(wgB) >= 1 }, time.Second, 5*time.Millisecond)

	// Recovery: re-bootstrap over signalling with the data path STILL broken. It must
	// still converge (signal is independent of the data path) on a fresh PSK.
	bootstrap(t, dA, dB)
	psk2 := wgB.psk("aaaa")
	require.NotEqual(t, psk1, psk2, "recovery derived a fresh PSK")
	require.Equal(t, psk2, wgA.psk("bbbb"), "both sides resync after recovery")
}

// TestConcurrency_ConcurrentRekeysNoRace hammers both managers with concurrent rotation
// clocks from many goroutines. Its primary job (with -race) is to prove the single-lock
// state machine has no data races or deadlocks under contention; a final deterministic
// bootstrap then asserts there is no split-brain (both sides on the same PSK).
func TestConcurrency_ConcurrentRekeysNoRace(t *testing.T) {
	dA, dB, wgA, wgB, _ := pair(t)
	defer dA.Stop()
	defer dB.Stop()

	bootstrap(t, dA, dB)

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				dB.OnDataPathRekeyed("aaaa", 0) // initiator chains a rotation
				dA.OnDataPathRekeyed("bbbb", 0) // responder side is a no-op, still stresses the lock
			}
		}()
	}
	wg.Wait()

	// The storm may leave an exchange mid-flight (concurrent cancellation). Force a
	// clean convergence over signalling, then assert no split-brain.
	bootstrap(t, dA, dB)
	a, b := wgA.psk("bbbb"), wgB.psk("aaaa")
	require.NotEqual(t, PSK{}, b)
	require.Equal(t, a, b, "both sides converge on the same PSK, no split-brain")
}
