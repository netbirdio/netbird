package server

import (
	log "github.com/sirupsen/logrus"
	"sync"
	"time"
)

// Scheduler is an interface which implementations can schedule and cancel jobs
type Scheduler interface {
	Cancel(IDs []string)
	Schedule(in time.Duration, ID string, job func() (reschedule bool, nextRunIn time.Duration))
}

// MockScheduler is a mock implementation of  Scheduler
type MockScheduler struct {
	CancelFunc   func(IDs []string)
	ScheduleFunc func(in time.Duration, ID string, job func() (reschedule bool, nextRunIn time.Duration))
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
func (mock *MockScheduler) Schedule(in time.Duration, ID string, job func() (reschedule bool, nextRunIn time.Duration)) {
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
		select {
		case cancel <- struct{}{}:
			log.Debugf("cancelled scheduled job %s", ID)
		default:
			log.Warnf("couldn't cancel job %s because there was no routine listening on the cancel event", ID)
			return false
		}

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
func (wm *DefaultScheduler) Schedule(in time.Duration, ID string, job func() (reschedule bool, nextRunIn time.Duration)) {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	cancel := make(chan struct{})
	if _, ok := wm.jobs[ID]; ok {
		log.Debugf("couldn't schedule a job %s because it already exists. There are %d total jobs scheduled.",
			ID, len(wm.jobs))
		return
	}

	wm.jobs[ID] = cancel
	log.Debugf("scheduled a job %s to run in %s. There are %d total jobs scheduled.", ID, in.String(), len(wm.jobs))
	go func() {
		select {
		case <-time.After(in):
			log.Debugf("time to do a scheduled job %s", ID)
			reschedule, runIn := job()
			wm.mu.Lock()
			defer wm.mu.Unlock()
			delete(wm.jobs, ID)
			if reschedule {
				go wm.Schedule(runIn, ID, job)
			}
		case <-cancel:
			log.Debugf("stopped scheduled job %s ", ID)
			wm.mu.Lock()
			defer wm.mu.Unlock()
			delete(wm.jobs, ID)
			return
		}
	}()
}
