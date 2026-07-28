package grpc

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRefreshInterval(t *testing.T) {
	defaultInterval := defaultDuration / 4 * 3

	require.Equal(t, 9*time.Hour, refreshInterval(12*time.Hour))
	require.Equal(t, defaultInterval, refreshInterval(0))
	require.Equal(t, defaultInterval, refreshInterval(-time.Second))
	require.Equal(t, defaultInterval, refreshInterval(3*time.Nanosecond))
	require.Positive(t, refreshInterval(4*time.Nanosecond))
}

func TestWorkerSkipsCancelledJob(t *testing.T) {
	var ran atomic.Int32
	scheduler := newRefreshScheduler(func(*refreshJob) {
		ran.Add(1)
	})

	cancelledJob := &refreshJob{interval: time.Hour}
	cancelledJob.cancelled.Store(true)
	liveJob := &refreshJob{interval: time.Hour}

	scheduler.work <- cancelledJob
	scheduler.work <- liveJob

	require.Eventually(t, func() bool {
		return ran.Load() == 1
	}, 2*time.Second, 10*time.Millisecond, "live job should run exactly once, cancelled job never")
}

func TestCancelBeforeFirePreventsRun(t *testing.T) {
	var ran atomic.Int32
	scheduler := newRefreshScheduler(func(*refreshJob) {
		ran.Add(1)
	})

	job := &refreshJob{interval: 50 * time.Millisecond}
	scheduler.schedule(job)
	scheduler.cancel(job)

	time.Sleep(150 * time.Millisecond)
	require.Zero(t, ran.Load(), "cancelled job must never fire")

	scheduler.mu.Lock()
	heapLen := len(scheduler.jobs)
	scheduler.mu.Unlock()
	require.Zero(t, heapLen)
}
