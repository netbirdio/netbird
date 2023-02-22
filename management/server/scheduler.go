package server

import (
	log "github.com/sirupsen/logrus"
	"sync"
	"time"
)

// Scheduler is a generic structure that allows to schedule jobs (functions) to run in the future and cancel them.
type Scheduler struct {
	// jobs map holds cancellation channels indexed by the job ID
	jobs map[string]chan struct{}
	mu   *sync.Mutex
}

func NewScheduler() *Scheduler {
	return &Scheduler{
		jobs: make(map[string]chan struct{}),
		mu:   &sync.Mutex{},
	}
}

func (wm *Scheduler) cancel(ID string) bool {
	cancel, ok := wm.jobs[ID]
	if ok {
		delete(wm.jobs, ID)
		cancel <- struct{}{}
		log.Debugf("cancelled scheduled job %s", ID)
	}
	return ok
}

// Cancel cancels the scheduled job by ID if present.
// If job wasn't found the function returns false.
func (wm *Scheduler) Cancel(IDs []string) {
	wm.mu.Lock()
	defer wm.mu.Unlock()

	for _, id := range IDs {
		wm.cancel(id)
	}
}

// Schedule a job to run in some time in the future. If job returns true then it will be scheduled one more time.
func (wm *Scheduler) Schedule(in time.Duration, ID string, job func() (reschedule bool, nextRunIn time.Duration)) {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	cancel := make(chan struct{})
	if _, ok := wm.jobs[ID]; !ok {
		wm.jobs[ID] = cancel
		log.Debugf("scheduled peer login expiration job for account %s to run in %s", ID, in.String())
		go func() {
			select {
			case <-time.After(in):
				log.Debugf("time to do a scheduled job %s", ID)
				wm.mu.Lock()
				defer wm.mu.Unlock()
				reschedule, runIn := job()
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
}
