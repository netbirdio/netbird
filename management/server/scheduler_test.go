package server

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"sync"
	"testing"
	"time"
)

func TestScheduler_Performance(t *testing.T) {
	scheduler := NewScheduler()
	n := 1000
	wg := sync.WaitGroup{}
	wg.Add(n)
	for i := 0; i < n; i++ {
		millis := time.Duration(rand.Intn(500-50)+50) * time.Millisecond
		go scheduler.Schedule(millis, fmt.Sprintf("test-scheduler-job-%d", i), func() (reschedule bool, nextRunIn time.Duration) {
			time.Sleep(millis)
			wg.Done()
			return false, 0
		})
	}

	assert.True(t, len(scheduler.jobs) > 0)
	wg.Wait()
	assert.Len(t, scheduler.jobs, 0)
}

func TestScheduler_Cancel(t *testing.T) {
	jobID1 := "test-scheduler-job-1"
	jobID2 := "test-scheduler-job-2"
	scheduler := NewScheduler()
	scheduler.Schedule(2*time.Second, jobID1, func() (reschedule bool, nextRunIn time.Duration) {
		return false, 0
	})
	scheduler.Schedule(2*time.Second, jobID2, func() (reschedule bool, nextRunIn time.Duration) {
		return false, 0
	})

	assert.Len(t, scheduler.jobs, 2)
	scheduler.Cancel([]string{jobID1})
	assert.Len(t, scheduler.jobs, 1)
	assert.NotNil(t, scheduler.jobs[jobID2])
}

func TestScheduler_Schedule(t *testing.T) {
	jobID := "test-scheduler-job-1"
	scheduler := NewScheduler()
	wg := sync.WaitGroup{}
	wg.Add(1)
	// job without reschedule should be triggered once
	job := func() (reschedule bool, nextRunIn time.Duration) {
		wg.Done()
		return false, 0
	}
	scheduler.Schedule(300*time.Millisecond, jobID, job)
	wg.Wait()

	// job with reschedule should be triggered at least twice
	wg = sync.WaitGroup{}
	wg.Add(2)
	job = func() (reschedule bool, nextRunIn time.Duration) {
		wg.Done()
		return true, 300 * time.Millisecond
	}

	scheduler.Schedule(300*time.Millisecond, jobID, job)
	wg.Wait()
	scheduler.cancel(jobID)

}
