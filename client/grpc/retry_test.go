package grpc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/netstate"
)

func TestRetryWakesOnNetworkChange(t *testing.T) {
	ns := netstate.New()
	attempts := 0
	operation := func() error {
		attempts++
		if attempts == 1 {
			return errors.New("cut by network change")
		}
		return nil
	}

	go func() {
		time.Sleep(20 * time.Millisecond)
		ns.Set(false)
	}()

	start := time.Now()
	err := Retry(context.Background(), operation, backoff.NewConstantBackOff(time.Minute), ns)

	require.NoError(t, err)
	assert.Equal(t, 2, attempts, "network change must cause one immediate retry")
	assert.Less(t, time.Since(start), time.Second, "the transition must cut the minute-long sleep short")
}

func TestRetryPermanentError(t *testing.T) {
	sentinel := errors.New("permission denied")
	operation := func() error {
		return backoff.Permanent(sentinel)
	}

	err := Retry(context.Background(), operation, backoff.NewConstantBackOff(time.Millisecond), nil)
	assert.ErrorIs(t, err, sentinel, "permanent errors must stop retries")
}

func TestRetryNilNetState(t *testing.T) {
	attempts := 0
	operation := func() error {
		attempts++
		if attempts < 3 {
			return errors.New("transient")
		}
		return nil
	}

	err := Retry(context.Background(), operation, backoff.NewConstantBackOff(time.Millisecond), nil)
	require.NoError(t, err)
	assert.Equal(t, 3, attempts, "nil network state must preserve timed retries")
}

func TestRetryStops(t *testing.T) {
	failure := errors.New("still failing")
	operation := func() error {
		return failure
	}

	err := Retry(context.Background(), operation, &backoff.StopBackOff{}, nil)
	assert.ErrorIs(t, err, failure, "stop backoff must return the operation error")
}

func TestRetryCtxCancelDuringSleep(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	operation := func() error {
		return errors.New("failing")
	}

	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := Retry(ctx, operation, backoff.NewConstantBackOff(time.Minute), netstate.New())

	assert.ErrorIs(t, err, context.Canceled, "context cancellation must stop the retry loop")
	assert.Less(t, time.Since(start), time.Second, "context cancellation must interrupt backoff sleep")
}
