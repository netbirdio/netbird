package server

import (
	"context"
	"fmt"
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScheduler_Performance(t *testing.T) {
	scheduler := NewDefaultScheduler()
	n := 500
	wg := &sync.WaitGroup{}
	wg.Add(n)
	maxMs := 500
	minMs := 50
	for i := 0; i < n; i++ {
		millis := time.Duration(rand.Intn(maxMs-minMs)+minMs) * time.Millisecond
		go scheduler.Schedule(context.Background(), millis, fmt.Sprintf("test-scheduler-job-%d", i), func() (nextRunIn time.Duration, reschedule bool) {
			time.Sleep(millis)
			wg.Done()
			return 0, false
		})
	}
	timeout := 3 * time.Second
	if runtime.GOOS == "windows" {
		// sleep and ticker are slower on windows see https://github.com/golang/go/issues/44343
		timeout = 5 * time.Second
	}

	failed := waitTimeout(wg, timeout)
	if failed {
		t.Fatal("timed out while waiting for test to finish")
		return
	}
	assert.Len(t, scheduler.jobs, 0)
}

func TestScheduler_Cancel(t *testing.T) {
	jobID1 := "test-scheduler-job-1"
	jobID2 := "test-scheduler-job-2"
	scheduler := NewDefaultScheduler()
	tChan := make(chan struct{})
	p := []string{jobID1, jobID2}
	scheduletime := 2 * time.Millisecond
	sleepTime := 4 * time.Millisecond
	if runtime.GOOS == "windows" {
		// sleep and ticker are slower on windows see https://github.com/golang/go/issues/44343
		sleepTime = 20 * time.Millisecond
	}

	scheduler.Schedule(context.Background(), scheduletime, jobID1, func() (nextRunIn time.Duration, reschedule bool) {
		tt := p[0]
		<-tChan
		t.Logf("job %s", tt)
		return scheduletime, true
	})
	scheduler.Schedule(context.Background(), scheduletime, jobID2, func() (nextRunIn time.Duration, reschedule bool) {
		return scheduletime, true
	})
	defer scheduler.Cancel(context.Background(), []string{jobID2})

	time.Sleep(sleepTime)
	assert.Len(t, scheduler.jobs, 2)
	scheduler.Cancel(context.Background(), []string{jobID1})
	close(tChan)
	p = []string{}
	time.Sleep(sleepTime)
	assert.Len(t, scheduler.jobs, 1)
	assert.NotNil(t, scheduler.jobs[jobID2])
}

func TestScheduler_CancelAll(t *testing.T) {
	jobID1 := "test-scheduler-job-1"
	jobID2 := "test-scheduler-job-2"
	scheduler := NewDefaultScheduler()
	tChan := make(chan struct{})
	p := []string{jobID1, jobID2}
	scheduletime := 2 * time.Millisecond
	sleepTime := 4 * time.Millisecond
	if runtime.GOOS == "windows" {
		// sleep and ticker are slower on windows see https://github.com/golang/go/issues/44343
		sleepTime = 20 * time.Millisecond
	}

	scheduler.Schedule(context.Background(), scheduletime, jobID1, func() (nextRunIn time.Duration, reschedule bool) {
		tt := p[0]
		<-tChan
		t.Logf("job %s", tt)
		return scheduletime, true
	})
	scheduler.Schedule(context.Background(), scheduletime, jobID2, func() (nextRunIn time.Duration, reschedule bool) {
		return scheduletime, true
	})

	time.Sleep(sleepTime)
	assert.Len(t, scheduler.jobs, 2)
	scheduler.CancelAll(context.Background())
	close(tChan)
	p = []string{}
	time.Sleep(sleepTime)
	assert.Len(t, scheduler.jobs, 0)
}

func TestScheduler_Schedule(t *testing.T) {
	jobID := "test-scheduler-job-1"
	scheduler := NewDefaultScheduler()
	wg := &sync.WaitGroup{}
	wg.Add(1)
	// job without reschedule should be triggered once
	job := func() (nextRunIn time.Duration, reschedule bool) {
		wg.Done()
		return 0, false
	}
	scheduler.Schedule(context.Background(), 300*time.Millisecond, jobID, job)
	failed := waitTimeout(wg, time.Second)
	if failed {
		t.Fatal("timed out while waiting for test to finish")
		return
	}

	// job with reschedule should be triggered at least twice
	wg = &sync.WaitGroup{}
	mx := &sync.Mutex{}
	scheduledTimes := 0
	wg.Add(2)
	job = func() (nextRunIn time.Duration, reschedule bool) {
		mx.Lock()
		defer mx.Unlock()
		// ensure we repeat only twice
		if scheduledTimes < 2 {
			wg.Done()
			scheduledTimes++
			return 300 * time.Millisecond, true
		}
		return 0, false
	}

	scheduler.Schedule(context.Background(), 300*time.Millisecond, jobID, job)
	failed = waitTimeout(wg, time.Second)
	if failed {
		t.Fatal("timed out while waiting for test to finish")
		return
	}
	scheduler.cancel(context.Background(), jobID)

}

func TestScheduler_Schedule_ResetsTickerAfterReturningInitialInterval(t *testing.T) {
	jobID := "test-scheduler-job-2"
	scheduler := NewDefaultScheduler()
	defer scheduler.Cancel(context.Background(), []string{jobID})

	initial := 30 * time.Millisecond
	stretched := 400 * time.Millisecond
	runs := make(chan time.Time, 3)
	count := 0
	// The first run stretches the period; the second returns the initial interval again,
	// which must shrink the period back instead of keeping the stretched one.
	job := func() (nextRunIn time.Duration, reschedule bool) {
		count++
		runs <- time.Now()
		switch count {
		case 1:
			return stretched, true
		case 2:
			return initial, true
		default:
			return 0, false
		}
	}
	scheduler.Schedule(context.Background(), initial, jobID, job)

	var stamps []time.Time
	for len(stamps) < 3 {
		select {
		case ts := <-runs:
			stamps = append(stamps, ts)
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out after %d runs", len(stamps))
		}
	}
	assert.Less(t, stamps[2].Sub(stamps[1]), stretched/2, "returning the initial interval must reset the stretched ticker")
}

func TestScheduler_Schedule_StaleCompletionKeepsReplacement(t *testing.T) {
	jobID := "test-scheduler-job-3"
	scheduler := NewDefaultScheduler()
	defer scheduler.Cancel(context.Background(), []string{jobID})

	started := make(chan struct{})
	release := make(chan struct{})
	staleJob := func() (nextRunIn time.Duration, reschedule bool) {
		close(started)
		<-release
		return 0, false
	}
	scheduler.Schedule(context.Background(), 10*time.Millisecond, jobID, staleJob)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the first job to start")
	}

	// Cancel the job while it is still executing and register a replacement under the
	// same ID, as the expiration paths do on a settings change.
	scheduler.Cancel(context.Background(), []string{jobID})
	var replacementRuns atomic.Int32
	scheduler.Schedule(context.Background(), 20*time.Millisecond, jobID, func() (nextRunIn time.Duration, reschedule bool) {
		replacementRuns.Add(1)
		return 20 * time.Millisecond, true
	})
	require.True(t, scheduler.IsSchedulerRunning(jobID), "replacement must be registered")

	// The stale job now completes without rescheduling; its cleanup must leave the
	// replacement's entry in place.
	close(release)
	assert.Never(t, func() bool { return !scheduler.IsSchedulerRunning(jobID) }, 200*time.Millisecond, 10*time.Millisecond,
		"stale completion must not drop the replacement job")

	var duplicateRuns atomic.Int32
	scheduler.Schedule(context.Background(), 10*time.Millisecond, jobID, func() (nextRunIn time.Duration, reschedule bool) {
		duplicateRuns.Add(1)
		return 10 * time.Millisecond, true
	})
	assert.Never(t, func() bool { return duplicateRuns.Load() > 0 }, 100*time.Millisecond, 10*time.Millisecond,
		"a duplicate schedule must be refused while the replacement is registered")

	scheduler.Cancel(context.Background(), []string{jobID})
	assert.False(t, scheduler.IsSchedulerRunning(jobID), "cancel must find and remove the replacement")
	runsAfterCancel := replacementRuns.Load()
	assert.Never(t, func() bool { return replacementRuns.Load() > runsAfterCancel+1 }, 150*time.Millisecond, 10*time.Millisecond,
		"the replacement must stop after cancel")
}
