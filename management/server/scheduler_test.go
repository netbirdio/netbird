package server

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
		go scheduler.Schedule(millis, fmt.Sprintf("test-scheduler-job-%d", i), func() (nextRunIn time.Duration, reschedule bool) {
			time.Sleep(millis)
			wg.Done()
			return 0, false
		})
	}
	failed := waitTimeout(wg, 3*time.Second)
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
	scheduler.Schedule(2*time.Millisecond, jobID1, func() (nextRunIn time.Duration, reschedule bool) {
		tt := p[0]
		<-tChan
		t.Logf("job %s", tt)
		return 2 * time.Millisecond, true
	})
	scheduler.Schedule(2*time.Millisecond, jobID2, func() (nextRunIn time.Duration, reschedule bool) {
		return 2 * time.Millisecond, true
	})

	time.Sleep(4 * time.Millisecond)
	assert.Len(t, scheduler.jobs, 2)
	scheduler.Cancel([]string{jobID1})
	close(tChan)
	p = []string{}
	time.Sleep(4 * time.Millisecond)
	assert.Len(t, scheduler.jobs, 1)
	assert.NotNil(t, scheduler.jobs[jobID2])
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
	scheduler.Schedule(300*time.Millisecond, jobID, job)
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

	scheduler.Schedule(300*time.Millisecond, jobID, job)
	failed = waitTimeout(wg, time.Second)
	if failed {
		t.Fatal("timed out while waiting for test to finish")
		return
	}
	scheduler.cancel(jobID)

}
