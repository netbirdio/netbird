package server

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/shared/management/proto"
)

const jobChannelBuffer = 100

type JobEvent struct {
	PeerID   string
	Request  *proto.JobRequest
	Response *proto.JobResponse
	Done     chan struct{} // closed when response arrives
}

type JobManager struct {
	mu           *sync.RWMutex
	jobChannels  map[string]chan *JobEvent // per-peer job streams
	pending      map[string]*JobEvent      // jobID → event, todo replace with database
	responseWait time.Duration
	metrics      telemetry.AppMetrics
}

func NewJobManager(metrics telemetry.AppMetrics) *JobManager {
	return &JobManager{
		jobChannels:  make(map[string]chan *JobEvent),
		pending:      make(map[string]*JobEvent),
		responseWait: 5 * time.Minute,
		metrics:      metrics,
	}
}

// CreateJobChannel creates or replaces a channel for a peer
func (jm *JobManager) CreateJobChannel(peerID string) chan *JobEvent {
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
func (jm *JobManager) SendJob(ctx context.Context, peerID string, req *proto.JobRequest) error {
	jm.mu.RLock()
	ch, ok := jm.jobChannels[peerID]
	jm.mu.RUnlock()
	if !ok {
		return fmt.Errorf("peer %s has no channel", peerID)
	}

	event := &JobEvent{
		PeerID:  peerID,
		Request: req,
		Done:    make(chan struct{}),
	}

	jm.mu.Lock()
	jm.pending[string(req.ID)] = event
	jm.mu.Unlock()

	select {
	case ch <- event:
	case <-time.After(5 * time.Second):
		jm.cleanup(string(req.ID))
		return fmt.Errorf("job channel full for peer %s", peerID)
	}

	select {
	case <-event.Done:
		return nil
	case <-time.After(jm.responseWait):
		jm.cleanup(string(req.ID))
		return fmt.Errorf("job %s timed out", req.ID)
	case <-ctx.Done():
		jm.cleanup(string(req.ID))
		return ctx.Err()
	}
}

// HandleResponse marks a job as finished and moves it to completed
func (jm *JobManager) HandleResponse(resp *proto.JobResponse) error {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	event, ok := jm.pending[string(resp.ID)]
	if !ok {
		return fmt.Errorf("job %s not found", resp.ID)
	}

	event.Response = resp
	close(event.Done)

	return nil
}

// GetJobResponse returns the job response if available
func (jm *JobManager) GetJobResponse(jobID string) (*proto.JobResponse, error) {
	jm.mu.RLock()
	defer jm.mu.RUnlock()

	if event, ok := jm.pending[jobID]; ok {
		return event.Response, nil
	}

	return nil, fmt.Errorf("job %s not found", jobID)
}

// CloseChannel closes a peer’s channel and cleans up its jobs
func (jm *JobManager) CloseChannel(peerID string) {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	if ch, ok := jm.jobChannels[peerID]; ok {
		close(ch)
		delete(jm.jobChannels, peerID)
	}

	for jobID, ev := range jm.pending {
		if ev.PeerID == peerID {
			close(ev.Done)
			delete(jm.pending, jobID)
		}
	}
}

// cleanup removes a pending job safely
func (jm *JobManager) cleanup(jobID string) {
	jm.mu.Lock()
	defer jm.mu.Unlock()

	if ev, ok := jm.pending[jobID]; ok {
		close(ev.Done)
		delete(jm.pending, jobID)
	}
}
