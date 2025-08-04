package server

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// Scheduler is an interface which implementations can schedule and cancel jobs
type Scheduler interface {
	Cancel(ctx context.Context, IDs []string)
	CancelAll(ctx context.Context)
	Schedule(ctx context.Context, in time.Duration, ID string, job func() (nextRunIn time.Duration, reschedule bool))
	IsSchedulerRunning(ID string) bool
}

// MockScheduler is a mock implementation of  Scheduler
type MockScheduler struct {
	CancelFunc             func(ctx context.Context, IDs []string)
	CancelAllFunc          func(ctx context.Context)
	ScheduleFunc           func(ctx context.Context, in time.Duration, ID string, job func() (nextRunIn time.Duration, reschedule bool))
	IsSchedulerRunningFunc func(ID string) bool
}

// Cancel mocks the Cancel function of the Scheduler interface
func (mock *MockScheduler) Cancel(ctx context.Context, IDs []string) {
	if mock.CancelFunc != nil {
		mock.CancelFunc(ctx, IDs)
		return
	}
	log.WithContext(ctx).Warnf("MockScheduler doesn't have Cancel function defined ")
}

// CancelAll mocks the CancelAll function of the Scheduler interface
func (mock *MockScheduler) CancelAll(ctx context.Context) {
	if mock.CancelAllFunc != nil {
		mock.CancelAllFunc(ctx)
		return
	}
	log.WithContext(ctx).Warnf("MockScheduler doesn't have CancelAll function defined ")
}

// Schedule mocks the Schedule function of the Scheduler interface
func (mock *MockScheduler) Schedule(ctx context.Context, in time.Duration, ID string, job func() (nextRunIn time.Duration, reschedule bool)) {
	if mock.ScheduleFunc != nil {
		mock.ScheduleFunc(ctx, in, ID, job)
		return
	}
	log.WithContext(ctx).Warnf("MockScheduler doesn't have Schedule function defined")
}

func (mock *MockScheduler) IsSchedulerRunning(ID string) bool {
	if mock.IsSchedulerRunningFunc != nil {
		return mock.IsSchedulerRunningFunc(ID)
	}
	log.Warnf("MockScheduler doesn't have IsSchedulerRunning function defined")
	return false
}

// DefaultScheduler is a generic structure that allows to schedule jobs (functions) to run in the future and cancel them.
type DefaultScheduler struct {
	// jobs map holds cancellation channels indexed by the job ID
	jobs map[string]chan struct{}
	mu   *sync.Mutex
}

func (wm *DefaultScheduler) CancelAll(ctx context.Context) {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	for id := range wm.jobs {
		wm.cancel(ctx, id)
	}
}

// NewDefaultScheduler creates an instance of a DefaultScheduler
func NewDefaultScheduler() *DefaultScheduler {
	return &DefaultScheduler{
		jobs: make(map[string]chan struct{}),
		mu:   &sync.Mutex{},
	}
}

func (wm *DefaultScheduler) cancel(ctx context.Context, ID string) bool {
	cancel, ok := wm.jobs[ID]
	if ok {
		delete(wm.jobs, ID)
		close(cancel)
		log.WithContext(ctx).Debugf("cancelled scheduled job %s", ID)
	}
	return ok
}

// Cancel cancels the scheduled job by ID if present.
// If job wasn't found the function returns false.
func (wm *DefaultScheduler) Cancel(ctx context.Context, IDs []string) {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	for _, id := range IDs {
		wm.cancel(ctx, id)
	}
}

// Schedule a job to run in some time in the future. If job returns true then it will be scheduled one more time.
// If job with the provided ID already exists, a new one won't be scheduled.
func (wm *DefaultScheduler) Schedule(ctx context.Context, in time.Duration, ID string, job func() (nextRunIn time.Duration, reschedule bool)) {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	cancel := make(chan struct{})
	if _, ok := wm.jobs[ID]; ok {
		log.WithContext(ctx).Debugf("couldn't schedule a job %s because it already exists. There are %d total jobs scheduled.",
			ID, len(wm.jobs))
		return
	}

	ticker := time.NewTicker(in)

	wm.jobs[ID] = cancel
	log.WithContext(ctx).Debugf("scheduled a job %s to run in %s. There are %d total jobs scheduled.", ID, in.String(), len(wm.jobs))
	go func() {
		for {
			select {
			case <-ticker.C:
				select {
				case <-cancel:
					log.WithContext(ctx).Debugf("scheduled job %s was canceled, stop timer", ID)
					ticker.Stop()
					return
				default:
					log.WithContext(ctx).Debugf("time to do a scheduled job %s", ID)
				}
				runIn, reschedule := job()
				if !reschedule {
					wm.mu.Lock()
					defer wm.mu.Unlock()
					delete(wm.jobs, ID)
					log.WithContext(ctx).Debugf("job %s is not scheduled to run again", ID)
					ticker.Stop()
					return
				}
				// we need this comparison to avoid resetting the ticker with the same duration and missing the current elapsesed time
				if runIn != in {
					ticker.Reset(runIn)
				}
			case <-cancel:
				log.WithContext(ctx).Debugf("job %s was canceled, stopping timer", ID)
				ticker.Stop()
				return
			}
		}

	}()
}

// IsSchedulerRunning checks if a job with the provided ID is scheduled to run
func (wm *DefaultScheduler) IsSchedulerRunning(ID string) bool {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	_, ok := wm.jobs[ID]
	return ok
}
