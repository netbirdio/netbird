package pqkem

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestManager_RotationResumesAfterTimeout covers a rotation whose offers are all lost.
// The timeout must leave the rotation chain usable: the next data-path rekey has to start
// a new rotation. Deleting the exchange on timeout stopped rotation for good, since a
// rekey only chains from an exchange awaiting it, and the failure count never reached the
// threshold that triggers a Signal re-bootstrap, despite the log promising a retry.
func TestManager_RotationResumesAfterTimeout(t *testing.T) {
	dA, dB, wgA, wgB, lbB := pair(t) // dB ("bbbb") initiator
	defer dA.Stop()
	defer dB.Stop()
	dB.retryInterval = 10 * time.Millisecond
	dB.maxRetries = 2

	bootstrap(t, dA, dB)
	boot := wgB.psk("aaaa")

	// Lose every rotation offer until the exchange times out.
	lbB.drop.Store(true)
	dB.OnDataPathRekeyed("aaaa", 0)
	require.Eventually(t, func() bool {
		dB.mu.Lock()
		defer dB.mu.Unlock()
		ex := dB.exchanges["aaaa"]
		return ex == nil || ex.state != stateAwaitingAnswer
	}, time.Second, 5*time.Millisecond, "the lost rotation must time out")
	lbB.drop.Store(false)

	dB.OnDataPathRekeyed("aaaa", 0)
	require.Eventually(t, func() bool {
		return wgB.psk("aaaa") != boot && wgA.psk("bbbb") == wgB.psk("aaaa")
	}, time.Second, 5*time.Millisecond, "the next rekey must start a rotation that converges")
	assert.Empty(t, wgB.failed, "a single lost rotation must not escalate to a re-bootstrap")
}

// TestManager_RepeatedRotationTimeoutsEscalate verifies the failure policy can complete:
// consecutive lost rotations must reach the rekey-failure threshold and hand recovery to
// the host. With rotation stopping after the first timeout the threshold was unreachable.
func TestManager_RepeatedRotationTimeoutsEscalate(t *testing.T) {
	dA, dB, _, wgB, lbB := pair(t) // dB ("bbbb") initiator
	defer dA.Stop()
	defer dB.Stop()
	dB.retryInterval = 10 * time.Millisecond
	dB.maxRetries = 2

	bootstrap(t, dA, dB)
	lbB.drop.Store(true)

	for i := 0; i < dB.maxRekeyFailures; i++ {
		dB.OnDataPathRekeyed("aaaa", 0)
		require.Eventually(t, func() bool {
			dB.mu.Lock()
			defer dB.mu.Unlock()
			ex := dB.exchanges["aaaa"]
			return ex == nil || ex.state != stateAwaitingAnswer
		}, time.Second, 5*time.Millisecond, "rotation %d must time out", i+1)
	}

	assert.Eventually(t, func() bool { return failedCount(wgB) == 1 }, time.Second, 5*time.Millisecond,
		"consecutive lost rotations must escalate to a rekey failure")
}
