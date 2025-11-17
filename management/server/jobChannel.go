package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

const jobChannelBuffer = 100

type JobEvent struct {
	PeerID   string
	Request  *proto.JobRequest
	Response *proto.JobResponse
}

type JobManager struct {
	mu           *sync.RWMutex
	jobChannels  map[string]chan *JobEvent // per-peer job streams
	pending      map[string]*JobEvent      // jobID → event
	responseWait time.Duration
	metrics      telemetry.AppMetrics
	Store        store.Store
}

func NewJobManager(metrics telemetry.AppMetrics, store store.Store) *JobManager {

	return &JobManager{
		jobChannels:  make(map[string]chan *JobEvent),
		pending:      make(map[string]*JobEvent),
		responseWait: 5 * time.Minute,
		metrics:      metrics,
		mu:           &sync.RWMutex{},
		Store:        store,
	}
}

// CreateJobChannel creates or replaces a channel for a peer
func (jm *JobManager) CreateJobChannel(ctx context.Context, accountID, peerID string) chan *JobEvent {
	// all pending jobs stored in db for this peer should be failed
	if err := jm.Store.MarkPendingJobsAsFailed(ctx, accountID, peerID, "Pending job cleanup: marked as failed automatically due to being stuck too long"); err != nil {
		log.WithContext(ctx).Error(err.Error())
	}

	jm.mu.Lock()
	defer jm.mu.Unlock()

	if ch, ok := jm.jobChannels[peerID]; ok {
		close(ch)
		delete(jm.jobChannels, peerID)
	}

	ch := make(chan *JobEvent, jobChannelBuffer)
	jm.jobChannels[peerID] = ch
	return ch
}

// SendJob sends a job to a peer and tracks it as pending
func (jm *JobManager) SendJob(ctx context.Context, accountID, peerID string, req *proto.JobRequest) error {
	jm.mu.RLock()
	ch, ok := jm.jobChannels[peerID]
	jm.mu.RUnlock()
	if !ok {
		return fmt.Errorf("peer %s has no channel", peerID)
	}

	event := &JobEvent{
		PeerID:  peerID,
		Request: req,
	}

	jm.mu.Lock()
	jm.pending[string(req.ID)] = event
	jm.mu.Unlock()

	select {
	case ch <- event:
	case <-time.After(jm.responseWait):
		jm.cleanup(ctx, accountID, string(req.ID), "timed out")
		return fmt.Errorf("job %s timed out", req.ID)
	case <-ctx.Done():
		jm.cleanup(ctx, accountID, string(req.ID), ctx.Err().Error())
		return ctx.Err()
	}
	return nil
}

// HandleResponse marks a job as finished and moves it to completed
func (jm *JobManager) HandleResponse(ctx context.Context, resp *proto.JobResponse) error {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	// todo: validate job ID and would be nice to use uuid text marshal instead of string
	jobID := string(resp.ID)

	event, ok := jm.pending[jobID]
	if !ok {
		return fmt.Errorf("job %s not found", jobID)
	}
	var job types.Job
	if err := job.ApplyResponse(resp); err != nil {
		return fmt.Errorf("invalid job response: %v", err)
	}
	//update or create the store for job response
	err := jm.Store.CompletePeerJob(ctx, &job)
	if err == nil {
		event.Response = resp
	}

	delete(jm.pending, jobID)
	return err
}

// CloseChannel closes a peer’s channel and cleans up its jobs
func (jm *JobManager) CloseChannel(ctx context.Context, accountID, peerID string) {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	if ch, ok := jm.jobChannels[peerID]; ok {
		close(ch)
		jm.jobChannels[peerID] = nil
		delete(jm.jobChannels, peerID)
	}

	for jobID, ev := range jm.pending {
		if ev.PeerID == peerID {
			// if the client disconnect and there is pending job then marke it as failed
			if err := jm.Store.MarkPendingJobsAsFailed(ctx, accountID, peerID, "Time out peer disconnected"); err != nil {
				log.WithContext(ctx).Errorf(err.Error())
			}
			delete(jm.pending, jobID)
		}
	}
}

// cleanup removes a pending job safely
func (jm *JobManager) cleanup(ctx context.Context, accountID, jobID string, reason string) {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	if ev, ok := jm.pending[jobID]; ok {
		if err := jm.Store.MarkPendingJobsAsFailed(ctx, accountID, ev.PeerID, reason); err != nil {
			log.WithContext(ctx).Errorf(err.Error())
		}
		delete(jm.pending, jobID)
	}
}

func (jm *JobManager) IsPeerConnected(peerID string) bool {
	jm.mu.RLock()
	defer jm.mu.RUnlock()

	_, ok := jm.jobChannels[peerID]
	return ok
}

func (jm *JobManager) IsPeerHasPendingJobs(peerID string) bool {
	jm.mu.RLock()
	defer jm.mu.RUnlock()

	for _, ev := range jm.pending {
		if ev.PeerID == peerID {
			return true
		}
	}
	return false
}
