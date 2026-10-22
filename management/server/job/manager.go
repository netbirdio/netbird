package job

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/internals/modules/peers"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

const (
	// QueuedTimeout is how long a job waits for the peer's job stream before it fails.
	QueuedTimeout = 2 * time.Minute
	// RunTimeout is how long a sent job may run before it fails. A debug bundle can take
	// up to 5 minutes, plus its upload.
	RunTimeout = 10 * time.Minute

	sweepInterval  = time.Minute
	enqueueTimeout = 10 * time.Second

	reasonNotPickedUp  = "not picked up: peer job stream unavailable"
	reasonNoResponse   = "no response from peer before deadline"
	reasonReconnected  = "job stream reconnected before the job finished"
	reasonStreamClosed = "job stream closed before the job was sent"
)

// ErrJobNotRunning is returned for an answer to a job that is not running on that peer:
// a late answer after the deadline, a duplicate, or another peer's job.
var ErrJobNotRunning = errors.New("job is not running on this peer")

type Event struct {
	PeerID  string
	Request *proto.JobRequest
}

// Notifier tells the management node that holds a peer's job stream that a job is
// queued for it. Deployments with several nodes provide one; the default delivers on
// this node only.
type Notifier interface {
	// JobQueued is called after a job is committed.
	JobQueued(ctx context.Context, accountID, peerID string)
	// StreamOpened is called before the node checks for queued jobs, so a job queued in
	// between still reaches it.
	StreamOpened(ctx context.Context, accountID, peerID string)
	StreamClosed(ctx context.Context, accountID, peerID string)
}

// Option configures a Manager.
type Option func(*Manager)

// WithNotifier replaces the default single-node notifier.
func WithNotifier(n Notifier) Option {
	return func(jm *Manager) {
		jm.notifier = n
	}
}

// Manager delivers remote jobs to peers. The jobs table is the source of truth: a job is
// persisted before it is sent, a node sends it only after claiming it in the database,
// and answers are matched in the database, so any node can create or complete a job.
type Manager struct {
	mu           sync.Mutex
	jobChannels  map[string]*Channel // per-peer job streams on this node
	metrics      telemetry.AppMetrics
	Store        store.Store
	peersManager peers.Manager
	notifier     Notifier

	sweepCancel context.CancelFunc
	sweepDone   chan struct{}
}

func NewJobManager(metrics telemetry.AppMetrics, store store.Store, peersManager peers.Manager, opts ...Option) *Manager {
	jm := &Manager{
		jobChannels:  make(map[string]*Channel),
		metrics:      metrics,
		Store:        store,
		peersManager: peersManager,
	}
	jm.notifier = localNotifier{jm: jm}
	for _, opt := range opts {
		opt(jm)
	}
	return jm
}

// JobQueued hands a committed job to the node holding the peer's job stream.
func (jm *Manager) JobQueued(ctx context.Context, accountID, peerID string) {
	jm.notifier.JobQueued(ctx, accountID, peerID)
}

// CreateJobChannel registers a job stream for the peer, replacing an older one on this
// node, and sends the jobs queued while the peer had no stream. Jobs sent on an earlier
// stream are failed: the peer reconnected, so it is no longer running them.
func (jm *Manager) CreateJobChannel(ctx context.Context, accountID, peerID string) *Channel {
	ch := NewChannel()

	jm.mu.Lock()
	if old, ok := jm.jobChannels[peerID]; ok {
		old.Close()
	}
	jm.jobChannels[peerID] = ch
	jm.mu.Unlock()

	jm.notifier.StreamOpened(ctx, accountID, peerID)

	if err := jm.Store.FailDispatchedPeerJobs(ctx, accountID, peerID, reasonReconnected); err != nil {
		log.WithContext(ctx).Errorf("failed to fail jobs of a previous stream of peer %s: %v", peerID, err)
	}
	jm.DeliverQueued(ctx, accountID, peerID)

	return ch
}

// DeliverQueued sends the peer's queued jobs if its job stream is on this node.
func (jm *Manager) DeliverQueued(ctx context.Context, accountID, peerID string) {
	jm.mu.Lock()
	ch, ok := jm.jobChannels[peerID]
	jm.mu.Unlock()
	if !ok {
		return
	}

	jobs, err := jm.Store.GetQueuedPeerJobs(ctx, accountID, peerID)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get queued jobs of peer %s: %v", peerID, err)
		return
	}
	for _, job := range jobs {
		jm.deliver(ctx, ch, accountID, peerID, job)
	}
}

func (jm *Manager) deliver(ctx context.Context, ch *Channel, accountID, peerID string, job *types.Job) {
	req, err := job.ToStreamJobRequest()
	if err != nil {
		log.WithContext(ctx).Errorf("failed to build job %s for peer %s: %v", job.ID, peerID, err)
		return
	}

	now := time.Now().UTC()
	claimed, err := jm.Store.ClaimPeerJob(ctx, accountID, peerID, job.ID, now, now.Add(RunTimeout))
	if err != nil {
		log.WithContext(ctx).Errorf("failed to claim job %s for peer %s: %v", job.ID, peerID, err)
		return
	}
	if !claimed {
		return
	}

	if err := ch.AddEvent(ctx, enqueueTimeout, &Event{PeerID: peerID, Request: req}); err != nil {
		failed := &types.Job{ID: job.ID, Status: types.JobStatusFailed, FailedReason: reasonStreamClosed, CompletedAt: &now}
		if _, err := jm.Store.CompleteDispatchedPeerJob(ctx, accountID, peerID, failed); err != nil {
			log.WithContext(ctx).Errorf("failed to fail unsent job %s: %v", job.ID, err)
		}
	}
}

// HandleResponse records a peer's answer to a job that was sent to it. The peer is the
// one authenticated on the stream, so a peer can only finish its own jobs.
func (jm *Manager) HandleResponse(ctx context.Context, accountID, peerID string, resp *proto.JobResponse) error {
	var job types.Job
	if err := job.ApplyResponse(resp); err != nil {
		return fmt.Errorf("invalid job response: %w", err)
	}

	completed, err := jm.Store.CompleteDispatchedPeerJob(ctx, accountID, peerID, &job)
	if err != nil {
		return fmt.Errorf("complete job %s: %w", job.ID, err)
	}
	if !completed {
		return fmt.Errorf("job %s: %w", job.ID, ErrJobNotRunning)
	}
	return nil
}

// CloseChannel closes the peer's job channel session. It does nothing when a newer job
// stream has registered a different channel for the peer. Jobs sent on the closed stream
// stay running until the peer reconnects or their deadline passes.
func (jm *Manager) CloseChannel(ctx context.Context, accountID, peerID string, session *Channel) {
	jm.mu.Lock()
	ch, ok := jm.jobChannels[peerID]
	if !ok || ch != session {
		jm.mu.Unlock()
		log.WithContext(ctx).Debugf("skipped closing job channel: peer %s is owned by a newer job stream", peerID)
		return
	}
	ch.Close()
	delete(jm.jobChannels, peerID)
	jm.mu.Unlock()

	jm.notifier.StreamClosed(ctx, accountID, peerID)
}

// StartSweeper fails jobs past their deadline once a minute until Stop. Every node may
// run it: each pass is a conditional update.
func (jm *Manager) StartSweeper() {
	jm.mu.Lock()
	defer jm.mu.Unlock()
	if jm.sweepCancel != nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	jm.sweepCancel, jm.sweepDone = cancel, done

	go func() {
		defer close(done)
		ticker := time.NewTicker(sweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				jm.failExpired(ctx)
			}
		}
	}()
}

// Stop stops the sweeper. It is safe to call more than once.
func (jm *Manager) Stop() {
	jm.mu.Lock()
	cancel, done := jm.sweepCancel, jm.sweepDone
	jm.sweepCancel, jm.sweepDone = nil, nil
	jm.mu.Unlock()

	if cancel != nil {
		cancel()
		<-done
	}
}

func (jm *Manager) failExpired(ctx context.Context) {
	now := time.Now().UTC()
	failed, err := jm.Store.FailExpiredPeerJobs(ctx, now, now.Add(-RunTimeout), reasonNotPickedUp, reasonNoResponse)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to fail expired jobs: %v", err)
		return
	}
	if failed > 0 {
		log.WithContext(ctx).Debugf("failed %d jobs past their deadline", failed)
	}
}

// localNotifier delivers on this node only, which is all a single management node needs.
type localNotifier struct {
	jm *Manager
}

func (n localNotifier) JobQueued(ctx context.Context, accountID, peerID string) {
	n.jm.DeliverQueued(ctx, accountID, peerID)
}

func (localNotifier) StreamOpened(context.Context, string, string) {}

func (localNotifier) StreamClosed(context.Context, string, string) {}
