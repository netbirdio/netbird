package job

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

type Event struct {
	PeerID   string
	Request  *proto.JobRequest
	Response *proto.JobResponse
}

type Manager struct {
	mu           *sync.RWMutex
	jobChannels  map[string]*Channel // per-peer job streams
	pending      map[string]*Event   // jobID → event
	responseWait time.Duration
	metrics      telemetry.AppMetrics
	Store        store.Store
}

func NewJobManager(metrics telemetry.AppMetrics, store store.Store) *Manager {

	return &Manager{
		jobChannels:  make(map[string]*Channel),
		pending:      make(map[string]*Event),
		responseWait: 5 * time.Minute,
		metrics:      metrics,
		mu:           &sync.RWMutex{},
		Store:        store,
	}
}

// CreateJobChannel creates or replaces a channel for a peer
func (jm *Manager) CreateJobChannel(ctx context.Context, accountID, peerID string) *Channel {
	// all pending jobs stored in db for this peer should be failed
	if err := jm.Store.MarkPendingJobsAsFailed(ctx, accountID, peerID, "Pending job cleanup: marked as failed automatically due to being stuck too long"); err != nil {
		log.WithContext(ctx).Error(err.Error())
	}

	jm.mu.Lock()
	defer jm.mu.Unlock()

	if ch, ok := jm.jobChannels[peerID]; ok {
		ch.Close()
		delete(jm.jobChannels, peerID)
	}

	ch := NewChannel()
	jm.jobChannels[peerID] = ch
	return ch
}

// SendJob sends a job to a peer and tracks it as pending
func (jm *Manager) SendJob(ctx context.Context, accountID, peerID string, req *proto.JobRequest) error {
	jm.mu.RLock()
	ch, ok := jm.jobChannels[peerID]
	jm.mu.RUnlock()
	if !ok {
		return fmt.Errorf("peer %s has no channel", peerID)
	}

	event := &Event{
		PeerID:  peerID,
		Request: req,
	}

	jm.mu.Lock()
	jm.pending[string(req.ID)] = event
	jm.mu.Unlock()

	if err := ch.AddEvent(ctx, jm.responseWait, event); err != nil {
		jm.cleanup(ctx, accountID, string(req.ID), err.Error())
		return err
	}

	return nil
}

// HandleResponse marks a job as finished and moves it to completed
func (jm *Manager) HandleResponse(ctx context.Context, resp *proto.JobResponse) error {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	// todo: validate job ID and would be nice to use uuid text marshal instead of string
	jobID := string(resp.ID)

	// todo: in this map has jobs for all peers in any account. Consider to validate the jobID association for the peer
	event, ok := jm.pending[jobID]
	if !ok {
		return fmt.Errorf("job %s not found", jobID)
	}
	var job types.Job
	// todo: ApplyResponse should be static. Any member value is unusable in this way
	if err := job.ApplyResponse(resp); err != nil {
		return fmt.Errorf("invalid job response: %v", err)
	}
	//update or create the store for job response
	err := jm.Store.CompletePeerJob(ctx, &job)
	// todo incorrect error handling. Why do we touch event if we drop it the next step?
	if err == nil {
		event.Response = resp
	}

	delete(jm.pending, jobID)
	return err
}

// CloseChannel closes a peer’s channel and cleans up its jobs
func (jm *Manager) CloseChannel(ctx context.Context, accountID, peerID string) {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	if ch, ok := jm.jobChannels[peerID]; ok {
		ch.Close()
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
func (jm *Manager) cleanup(ctx context.Context, accountID, jobID string, reason string) {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	if ev, ok := jm.pending[jobID]; ok {
		if err := jm.Store.MarkPendingJobsAsFailed(ctx, accountID, ev.PeerID, reason); err != nil {
			log.WithContext(ctx).Errorf(err.Error())
		}
		delete(jm.pending, jobID)
	}
}

func (jm *Manager) IsPeerConnected(peerID string) bool {
	jm.mu.RLock()
	defer jm.mu.RUnlock()

	_, ok := jm.jobChannels[peerID]
	return ok
}

func (jm *Manager) IsPeerHasPendingJobs(peerID string) bool {
	jm.mu.RLock()
	defer jm.mu.RUnlock()

	for _, ev := range jm.pending {
		if ev.PeerID == peerID {
			return true
		}
	}
	return false
}
