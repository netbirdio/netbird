//go:build !js

package grpc

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/hbwatch"
)

// The device slept through a 10 s backoff: the wall clock moved 3 min, the
// timer did not. The device wake ends the wait and the retry goes at once.
func TestRetryWaitEndsAtWakeOnWallClock(t *testing.T) {
	clk := &offsetClock{}
	w := hbwatch.New(clk, time.Minute)
	t.Cleanup(hbwatch.SetDefault(w))

	var attempts atomic.Int32
	operation := func() error {
		if attempts.Add(1) == 1 {
			return errors.New("server gone")
		}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() {
		done <- Retry(ctx, operation, backoff.NewConstantBackOff(10*time.Second), nil, hbwatch.WaitSync)
	}()

	require.Eventually(t, func() bool { return attempts.Load() == 1 }, time.Second, 5*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	w.SetDeviceAsleep(false)
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int32(1), attempts.Load(), "a wake before the wall deadline must not retry")

	clk.jump(3 * time.Minute)
	w.SetDeviceAsleep(false)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("the wake past the wall deadline must start the retry")
	}
	assert.Equal(t, int32(2), attempts.Load())
}
