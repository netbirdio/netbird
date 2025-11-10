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
// It manages a map of scheduled jobs, each with its own cancellation channel and goroutine.
// The scheduler is thread-safe and handles job lifecycle including cleanup on cancellation or completion.
type DefaultScheduler struct {
	// jobs map holds cancellation channels indexed by the job ID
	// Each channel is used to signal cancellation to the job's goroutine
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

// Schedule schedules a job to run after the specified duration. The job function is called
// and can return a new duration and a boolean indicating whether to reschedule.
//
// If the job returns reschedule=true, it will be scheduled again after the returned duration.
// If reschedule=false, the job is removed from the scheduler and will not run again.
//
// If a job with the same ID already exists, the new job will not be scheduled.
//
// Parameters:
//   - ctx: Context for logging and cancellation propagation
//   - in: Initial duration before the job runs
//   - ID: Unique identifier for the job (used to prevent duplicates and for cancellation)
//   - job: Function to execute. Returns (nextRunIn, reschedule) where nextRunIn is the
//     duration until the next run (if reschedule is true), and reschedule indicates
//     whether to schedule the job again.
//
// Thread-safety: This method is safe for concurrent use. The job function itself
// should be thread-safe if it accesses shared state.
//
// Resource management: Each scheduled job runs in its own goroutine. The goroutine
// is properly cleaned up when the job completes or is cancelled. The ticker is
// always stopped via defer to prevent resource leaks.
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
		defer func() {
			// Ensure ticker is stopped even if job panics
			ticker.Stop()
			// Recover from panic to prevent goroutine crash
			if r := recover(); r != nil {
				log.WithContext(ctx).Errorf("job %s panicked: %v", ID, r)
				// Clean up job from map
				wm.mu.Lock()
				delete(wm.jobs, ID)
				wm.mu.Unlock()
			}
		}()

		for {
			select {
			case <-ticker.C:
				select {
				case <-cancel:
					log.WithContext(ctx).Debugf("scheduled job %s was canceled, stop timer", ID)
					return
				default:
					log.WithContext(ctx).Debugf("time to do a scheduled job %s", ID)
				}
				runIn, reschedule := job()
				if !reschedule {
					// Job requested to stop - remove from map and exit goroutine
					// We need to lock here to safely delete from the map
					// This is safe even if Cancel is called concurrently because:
					// 1. We hold the lock while deleting
					// 2. The cancel channel is already in the map, so Cancel will close it
					// 3. We return immediately after deleting, so the goroutine exits
					wm.mu.Lock()
					// Check if job still exists (might have been cancelled)
					if _, exists := wm.jobs[ID]; exists {
					delete(wm.jobs, ID)
					}
					wm.mu.Unlock()
					log.WithContext(ctx).Debugf("job %s is not scheduled to run again", ID)
					return
				}
				// we need this comparison to avoid resetting the ticker with the same duration and missing the current elapsesed time
				if runIn != in {
					ticker.Reset(runIn)
				}
			case <-cancel:
				log.WithContext(ctx).Debugf("job %s was canceled, stopping timer", ID)
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
