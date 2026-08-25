package netsweep

import (
	"context"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/stretchr/testify/assert"
)

func TestQuickRetryAfterRecentMark(t *testing.T) {
	sweeper := New()
	sweeper.MarkNetworkChange()

	slow := backoff.NewConstantBackOff(5 * time.Second)
	bo := sweeper.QuickRetryBackoff(context.Background(), slow, nil)

	assert.Equal(t, quickRetryDelay, bo.NextBackOff(), "first retry after a mark must be quick")
	assert.Equal(t, 5*time.Second, bo.NextBackOff(), "second retry must fall back to the wrapped backoff")

	bo.Reset()
	assert.Equal(t, quickRetryDelay, bo.NextBackOff(), "reset must re-arm the quick retry")
}

func TestQuickRetryWithoutMarkKeepsSpread(t *testing.T) {
	sweeper := New()

	slow := backoff.NewConstantBackOff(5 * time.Second)
	bo := sweeper.QuickRetryBackoff(context.Background(), slow, nil)

	assert.Equal(t, 5*time.Second, bo.NextBackOff(), "without a mark the wrapped backoff decides")

	sweeper.mu.Lock()
	sweeper.lastMark = time.Now().Add(-recentMarkWindow)
	sweeper.mu.Unlock()
	assert.Equal(t, 5*time.Second, bo.NextBackOff(), "a stale mark must not trigger the quick retry")
}

func TestQuickRetryNilSweeperPassthrough(t *testing.T) {
	var sweeper *Sweeper

	slow := backoff.NewConstantBackOff(5 * time.Second)
	bo := sweeper.QuickRetryBackoff(context.Background(), slow, nil)

	assert.Equal(t, backoff.BackOff(slow), bo, "nil sweeper must return the backoff unchanged")
}

func TestQuickRetryHonorsContext(t *testing.T) {
	sweeper := New()
	sweeper.MarkNetworkChange()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	bo := sweeper.QuickRetryBackoff(ctx, backoff.NewConstantBackOff(time.Millisecond), nil)

	assert.Equal(t, backoff.Stop, bo.NextBackOff(), "cancelled context must stop the retry loop")
}
