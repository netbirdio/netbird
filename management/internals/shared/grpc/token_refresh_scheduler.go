package grpc

import (
	"container/heap"
	"context"
	"sync"
	"time"
)

const (
	refreshWorkerCount   = 4
	refreshWorkQueueSize = 1024
)

type refreshKind int

const (
	refreshKindTURN refreshKind = iota
	refreshKindRelay
)

type refreshJob struct {
	ctx       context.Context
	accountID string
	peerID    string
	kind      refreshKind
	interval  time.Duration
	nextRun   time.Time
	index     int
}

type refreshJobHeap []*refreshJob

func (h refreshJobHeap) Len() int           { return len(h) }
func (h refreshJobHeap) Less(i, j int) bool { return h[i].nextRun.Before(h[j].nextRun) }

func (h refreshJobHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *refreshJobHeap) Push(x any) {
	job := x.(*refreshJob)
	job.index = len(*h)
	*h = append(*h, job)
}

func (h *refreshJobHeap) Pop() any {
	old := *h
	n := len(old)
	job := old[n-1]
	old[n-1] = nil
	job.index = -1
	*h = old[:n-1]
	return job
}

// refreshScheduler executes periodic credential refresh jobs for all peers
// from one timer goroutine and a fixed worker pool, instead of two parked
// goroutines per connected peer.
type refreshScheduler struct {
	mu   sync.Mutex
	jobs refreshJobHeap
	wake chan struct{}
	work chan *refreshJob
	run  func(job *refreshJob)
}

func newRefreshScheduler(run func(job *refreshJob)) *refreshScheduler {
	s := &refreshScheduler{
		wake: make(chan struct{}, 1),
		work: make(chan *refreshJob, refreshWorkQueueSize),
		run:  run,
	}
	go s.loop()
	for range refreshWorkerCount {
		go s.worker()
	}
	return s
}

func (s *refreshScheduler) schedule(job *refreshJob) {
	s.mu.Lock()
	job.nextRun = time.Now().Add(job.interval)
	heap.Push(&s.jobs, job)
	s.mu.Unlock()

	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *refreshScheduler) cancel(job *refreshJob) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if job.index >= 0 {
		heap.Remove(&s.jobs, job.index)
	}
}

func (s *refreshScheduler) loop() {
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}

	for {
		s.mu.Lock()
		now := time.Now()
		var due []*refreshJob
		for len(s.jobs) > 0 && !s.jobs[0].nextRun.After(now) {
			job := s.jobs[0]
			job.nextRun = job.nextRun.Add(job.interval)
			if !job.nextRun.After(now) {
				job.nextRun = now.Add(job.interval)
			}
			heap.Fix(&s.jobs, 0)
			due = append(due, job)
		}
		wait := time.Duration(-1)
		if len(s.jobs) > 0 {
			wait = time.Until(s.jobs[0].nextRun)
		}
		s.mu.Unlock()

		for _, job := range due {
			s.work <- job
		}

		if wait < 0 {
			<-s.wake
			continue
		}

		timer.Reset(wait)
		select {
		case <-s.wake:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
		}
	}
}

func (s *refreshScheduler) worker() {
	for job := range s.work {
		s.run(job)
	}
}
