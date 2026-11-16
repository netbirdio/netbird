package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/hbwatch"
)

// retryHeld waits until Signal registered on w, then reports whether w holds a
// Management retry on a sleeping device past the fast window, with no
// heartbeat wake yet.
func retryHeld(t *testing.T, w *hbwatch.Watcher, clk *jumpClock) bool {
	t.Helper()
	require.Eventually(t, func() bool {
		for _, s := range w.Snapshot().Streams {
			if s.Service == hbwatch.Signal {
				return true
			}
		}
		return false
	}, 5*time.Second, 10*time.Millisecond, "Signal must register")
	w.SetDeviceAsleep(true)
	down := clk.Now().Add(-hbwatch.FastRetryWindow - time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := w.WaitManagementRetry(ctx, hbwatch.RetrySync, down, nil)
	return errors.Is(err, context.DeadlineExceeded)
}

func newGateWatcher(t *testing.T) (*hbwatch.Watcher, *jumpClock) {
	t.Helper()
	clk := &jumpClock{now: time.Now()}
	w := hbwatch.New(clk, 30*time.Second)
	t.Cleanup(hbwatch.SetDefault(w))
	return w, clk
}

// A stream the server answered with a phase will bring a heartbeat wake, so it
// holds Management retries before its first heartbeat.
func TestSignalOpenedAlignedHoldsManagementRetry(t *testing.T) {
	w, clk := newGateWatcher(t)
	setAlignedRequest(t, 60*time.Second, true)
	srv := newRecordingSignalServer(t, false)
	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	storeTestSignedPhase(t, key, 60*time.Second)
	client := connectAlignedTestClientWithKey(t, srv, key)
	_, ok := client.alignedHeartbeat()
	require.True(t, ok, "precondition: the stream opened aligned")

	assert.True(t, retryHeld(t, w, clk), "an aligned Signal stream must hold the retry before its first heartbeat")
}

// A stream waiting for a signed phase sends no heartbeat yet, so it holds
// nothing.
func TestSignalWaitingForPhaseDoesNotHoldManagementRetry(t *testing.T) {
	w, clk := newGateWatcher(t)
	setAlignedRequest(t, 60*time.Second, true)
	srv := newRecordingSignalServer(t, false)
	client, _ := connectAlignedTestClient(t, srv)
	_, ok := client.alignedHeartbeat()
	require.False(t, ok, "precondition: the stream waits for a signed phase")

	assert.False(t, retryHeld(t, w, clk), "a stream without a phase must not hold the retry")
}
