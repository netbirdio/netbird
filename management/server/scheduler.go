package server

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// Scheduler is an interface which implementations can schedule and cancel jobs
type Scheduler interface {
	Cancel(IDs []string)
	Schedule(in time.Duration, ID string, job func() (nextRunIn time.Duration, reschedule bool))
}

// MockScheduler is a mock implementation of  Scheduler
type MockScheduler struct {
	CancelFunc   func(IDs []string)
	ScheduleFunc func(in time.Duration, ID string, job func() (nextRunIn time.Duration, reschedule bool))
}

// Cancel mocks the Cancel function of the Scheduler interface
func (mock *MockScheduler) Cancel(IDs []string) {
	if mock.CancelFunc != nil {
		mock.CancelFunc(IDs)
		return
	}
	log.Errorf("MockScheduler doesn't have Cancel function defined ")
}

// Schedule mocks the Schedule function of the Scheduler interface
func (mock *MockScheduler) Schedule(in time.Duration, ID string, job func() (nextRunIn time.Duration, reschedule bool)) {
	if mock.ScheduleFunc != nil {
		mock.ScheduleFunc(in, ID, job)
		return
	}
	log.Errorf("MockScheduler doesn't have Schedule function defined")
}

// DefaultScheduler is a generic structure that allows to schedule jobs (functions) to run in the future and cancel them.
type DefaultScheduler struct {
	// jobs map holds cancellation channels indexed by the job ID
	jobs map[string]chan struct{}
	mu   *sync.Mutex
}

// NewDefaultScheduler creates an instance of a DefaultScheduler
func NewDefaultScheduler() *DefaultScheduler {
	return &DefaultScheduler{
		jobs: make(map[string]chan struct{}),
		mu:   &sync.Mutex{},
	}
}

func (wm *DefaultScheduler) cancel(ID string) bool {
	cancel, ok := wm.jobs[ID]
	if ok {
		delete(wm.jobs, ID)
		close(cancel)
		log.Debugf("cancelled scheduled job %s", ID)
	}
	return ok
}

// Cancel cancels the scheduled job by ID if present.
// If job wasn't found the function returns false.
func (wm *DefaultScheduler) Cancel(IDs []string) {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	for _, id := range IDs {
		wm.cancel(id)
	}
}

// Schedule a job to run in some time in the future. If job returns true then it will be scheduled one more time.
// If job with the provided ID already exists, a new one won't be scheduled.
func (wm *DefaultScheduler) Schedule(in time.Duration, ID string, job func() (nextRunIn time.Duration, reschedule bool)) {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	cancel := make(chan struct{})
	if _, ok := wm.jobs[ID]; ok {
		log.Debugf("couldn't schedule a job %s because it already exists. There are %d total jobs scheduled.",
			ID, len(wm.jobs))
		return
	}

	ticker := time.NewTicker(in)

	wm.jobs[ID] = cancel
	log.Debugf("scheduled a job %s to run in %s. There are %d total jobs scheduled.", ID, in.String(), len(wm.jobs))
	go func() {
		for {
			select {
			case <-ticker.C:
				select {
				case <-cancel:
					log.Debugf("scheduled job %s was canceled, stop timer", ID)
					ticker.Stop()
					return
				default:
					log.Debugf("time to do a scheduled job %s", ID)
				}
				runIn, reschedule := job()
				if !reschedule {
					wm.mu.Lock()
					defer wm.mu.Unlock()
					delete(wm.jobs, ID)
					log.Debugf("job %s is not scheduled to run again", ID)
					ticker.Stop()
					return
				}
				// we need this comparison to avoid resetting the ticker with the same duration and missing the current elapsesed time
				if runIn != in {
					ticker.Reset(runIn)
				}
			case <-cancel:
				log.Debugf("job %s was canceled, stopping timer", ID)
				ticker.Stop()
				return
			}
		}

	}()
}
