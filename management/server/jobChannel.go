package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
	log "github.com/sirupsen/logrus"
)

const jobChannelBuffer = 100

type JobEvent struct {
	Job        *types.Job
	Request    *proto.JobRequest
	Response   *proto.JobResponse
	Done       chan struct{} // closed when response arrives
	StoreEvent func(meta map[string]any, peer *nbpeer.Peer)
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
func (jm *JobManager) CreateJobChannel(ctx context.Context, accountID, peerID string) (chan *JobEvent, error) {
	// all pending jobs stored in db for this peer should be failed
	if err := jm.Store.MarkPendingJobsAsFailed(ctx, accountID, peerID, "Pending job cleanup: marked as failed automatically due to being stuck too long"); err != nil {
		return nil, err
	}

	jm.mu.Lock()
	defer jm.mu.Unlock()

	if ch, ok := jm.jobChannels[peerID]; ok {
		close(ch)
		delete(jm.jobChannels, peerID)
	}

	ch := make(chan *JobEvent, jobChannelBuffer)
	jm.jobChannels[peerID] = ch
	return ch, nil
}

// SendJob sends a job to a peer and tracks it as pending
func (jm *JobManager) SendJob(ctx context.Context, job *types.Job, storeEvent func(meta map[string]any, peer *nbpeer.Peer)) error {
	jm.mu.RLock()
	ch, ok := jm.jobChannels[job.PeerID]
	jm.mu.RUnlock()
	if !ok {
		return fmt.Errorf("peer %s has no channel", job.PeerID)
	}

	req, err := job.ToStreamJobRequest()
	if err != nil {
		return err
	}

	event := &JobEvent{
		Job:        job,
		Request:    req,
		Done:       make(chan struct{}),
		StoreEvent: storeEvent,
	}

	jm.mu.Lock()
	jm.pending[string(req.ID)] = event
	jm.mu.Unlock()

	select {
	case ch <- event:
	case <-time.After(5 * time.Second):
		jm.cleanup(ctx, string(req.ID), "timed out")
		return fmt.Errorf("job channel full for peer %s", job.PeerID)
	}

	select {
	case <-event.Done:
		return nil
	case <-time.After(jm.responseWait):
		jm.cleanup(ctx, string(req.ID), "timed out")
		return fmt.Errorf("job %s timed out", req.ID)
	case <-ctx.Done():
		jm.cleanup(ctx, string(req.ID), ctx.Err().Error())
		return ctx.Err()
	}
}

// HandleResponse marks a job as finished and moves it to completed
func (jm *JobManager) HandleResponse(ctx context.Context, resp *proto.JobResponse) error {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	event, ok := jm.pending[string(resp.ID)]
	if !ok {
		return fmt.Errorf("job %s not found", resp.ID)
	}
	fmt.Printf("we got this %+v\n", resp)
	//update or create the store for job response
	err := jm.saveJob(ctx, event.Job, resp, event.StoreEvent)
	if err == nil {
		event.Response = resp
	}

	close(event.Done)
	delete(jm.pending, string(resp.ID))

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
		if ev.Job.PeerID == peerID {
			// if the client disconnect and there is pending job then marke it as failed
			if err := jm.Store.MarkPendingJobsAsFailed(ctx, accountID, peerID, "Time out"); err != nil {
				log.WithContext(ctx).Errorf(err.Error())
			}
			delete(jm.pending, jobID)
		}
	}
}

// cleanup removes a pending job safely
func (jm *JobManager) cleanup(ctx context.Context, jobID string, reason string) {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	if ev, ok := jm.pending[jobID]; ok {
		close(ev.Done)
		if err := jm.Store.MarkPendingJobsAsFailed(ctx, ev.Job.AccountID, ev.Job.PeerID, reason); err != nil {
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
		if ev.Job.PeerID == peerID {
			return true
		}
	}
	return false
}

func (jm *JobManager) saveJob(ctx context.Context, job *types.Job, response *proto.JobResponse, StoreEvent func(meta map[string]any, peer *nbpeer.Peer)) error {
	var peer *nbpeer.Peer
	var err error
	var eventsToStore func()

	// persist job in DB only if send succeeded
	err = jm.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		peer, err = transaction.GetPeerByID(ctx, store.LockingStrengthUpdate, job.AccountID, job.PeerID)
		if err != nil {
			return err
		}
		if err := transaction.CreateOrUpdatePeerJob(ctx, job, response); err != nil {
			return err
		}

		jobMeta := map[string]any{
			"job_id":       job.ID,
			"for_peer_id":  job.PeerID,
			"job_type":     job.Workload.Type,
			"job_status":   job.Status,
			"job_workload": job.Workload,
		}

		eventsToStore = func() {
			StoreEvent(jobMeta, peer)
		}
		return nil
	})
	if err != nil {
		return err
	}
	eventsToStore()
	return nil
}
