package job

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
	"github.com/netbirdio/netbird/shared/management/proto"
)

const (
	testAccount = "account-1"
	testPeer    = "peer-1"
)

func newTestStore(t *testing.T) store.Store {
	t.Helper()
	s, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	return s
}

func queueJob(t *testing.T, s store.Store, id string) {
	t.Helper()
	params, err := json.Marshal(api.BundleParameters{LogFileCount: 1})
	require.NoError(t, err)
	deadline := time.Now().UTC().Add(QueuedTimeout)
	require.NoError(t, s.CreatePeerJob(context.Background(), &types.Job{
		ID:         id,
		AccountID:  testAccount,
		PeerID:     testPeer,
		Status:     types.JobStatusPending,
		CreatedAt:  time.Now().UTC(),
		DeadlineAt: &deadline,
		Workload:   types.Workload{Type: types.JobTypeBundle, Parameters: params},
	}))
}

func jobStatus(t *testing.T, s store.Store, id string) *types.Job {
	t.Helper()
	job, err := s.GetPeerJobByID(context.Background(), testAccount, testPeer, id)
	require.NoError(t, err)
	return job
}

func receive(t *testing.T, ch *Channel) *Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	event, err := ch.Event(ctx)
	require.NoError(t, err, "a job should have been sent on the stream")
	return event
}

func assertNothingSent(t *testing.T, ch *Channel) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := ch.Event(ctx)
	assert.ErrorIs(t, err, context.DeadlineExceeded, "no job should have been sent")
}

func succeeded(id string) *proto.JobResponse {
	return &proto.JobResponse{
		ID:              []byte(id),
		Status:          proto.JobStatus_succeeded,
		WorkloadResults: &proto.JobResponse_Bundle{Bundle: &proto.BundleResult{UploadKey: "key"}},
	}
}

// Two managers over one store stand in for two management nodes: the job is created
// on a node without the peer's stream and is sent once the stream opens elsewhere.
func TestJobQueuedOnOtherNode_SentWhenStreamOpens(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	restNode := NewJobManager(nil, s, nil)
	grpcNode := NewJobManager(nil, s, nil)

	queueJob(t, s, "job-1")
	restNode.JobQueued(ctx, testAccount, testPeer)

	ch := grpcNode.CreateJobChannel(ctx, testAccount, testPeer)
	event := receive(t, ch)
	assert.Equal(t, []byte("job-1"), event.Request.ID)
	assert.NotNil(t, jobStatus(t, s, "job-1").DispatchedAt, "the sent job should be marked as dispatched")

	// The answer is accepted on any node.
	require.NoError(t, restNode.HandleResponse(ctx, testAccount, testPeer, succeeded("job-1")))
	assert.Equal(t, types.JobStatusSucceeded, jobStatus(t, s, "job-1").Status)
}

func TestJobQueued_SentOnLocalStream(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	jm := NewJobManager(nil, s, nil)

	ch := jm.CreateJobChannel(ctx, testAccount, testPeer)
	assertNothingSent(t, ch)

	queueJob(t, s, "job-1")
	jm.JobQueued(ctx, testAccount, testPeer)

	assert.Equal(t, []byte("job-1"), receive(t, ch).Request.ID)
}

// Both nodes see the job, but only the one that wins the claim sends it.
func TestJobSentOnce(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	nodeA := NewJobManager(nil, s, nil)
	nodeB := NewJobManager(nil, s, nil)

	chA := nodeA.CreateJobChannel(ctx, testAccount, testPeer)
	chB := nodeB.CreateJobChannel(ctx, testAccount, testPeer)

	queueJob(t, s, "job-1")
	nodeA.DeliverQueued(ctx, testAccount, testPeer)
	nodeB.DeliverQueued(ctx, testAccount, testPeer)

	receive(t, chA)
	assertNothingSent(t, chB)
}

func TestReconnect_FailsSentJobAndSendsQueued(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	nodeA := NewJobManager(nil, s, nil)
	nodeB := NewJobManager(nil, s, nil)

	chA := nodeA.CreateJobChannel(ctx, testAccount, testPeer)
	queueJob(t, s, "running")
	nodeA.JobQueued(ctx, testAccount, testPeer)
	receive(t, chA)

	queueJob(t, s, "queued")

	chB := nodeB.CreateJobChannel(ctx, testAccount, testPeer)

	running := jobStatus(t, s, "running")
	assert.Equal(t, types.JobStatusFailed, running.Status, "the job sent on the old stream should fail")
	assert.Equal(t, reasonReconnected, running.FailedReason)
	assert.Equal(t, []byte("queued"), receive(t, chB).Request.ID, "the queued job should go out on the new stream")
}

func TestHandleResponse_RejectsJobNotRunningOnPeer(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	jm := NewJobManager(nil, s, nil)

	queueJob(t, s, "job-1")
	err := jm.HandleResponse(ctx, testAccount, testPeer, succeeded("job-1"))
	assert.ErrorIs(t, err, ErrJobNotRunning, "an answer to a job that was never sent must be rejected")

	ch := jm.CreateJobChannel(ctx, testAccount, testPeer)
	receive(t, ch)

	err = jm.HandleResponse(ctx, testAccount, "other-peer", succeeded("job-1"))
	assert.ErrorIs(t, err, ErrJobNotRunning, "another peer must not finish this job")
	assert.Equal(t, types.JobStatusPending, jobStatus(t, s, "job-1").Status)
}

func TestCloseChannel_KeepsNewerSession(t *testing.T) {
	ctx := context.Background()
	jm := NewJobManager(nil, newTestStore(t), nil)

	stale := jm.CreateJobChannel(ctx, testAccount, testPeer)
	current := jm.CreateJobChannel(ctx, testAccount, testPeer)

	_, err := stale.Event(ctx)
	assert.ErrorIs(t, err, ErrJobChannelClosed, "the replaced channel should be closed")

	jm.CloseChannel(ctx, testAccount, testPeer, stale)

	event := &Event{PeerID: testPeer}
	require.NoError(t, current.AddEvent(ctx, time.Second, event))
	got, err := current.Event(ctx)
	require.NoError(t, err, "the newer session channel must stay open")
	assert.Equal(t, event, got)
}

type recordingNotifier struct {
	calls []string
}

func (n *recordingNotifier) JobQueued(context.Context, string, string) {
	n.calls = append(n.calls, "queued")
}

func (n *recordingNotifier) StreamOpened(context.Context, string, string) {
	n.calls = append(n.calls, "opened")
}

func (n *recordingNotifier) StreamClosed(context.Context, string, string) {
	n.calls = append(n.calls, "closed")
}

func TestNotifier_CalledOnQueueOpenAndClose(t *testing.T) {
	ctx := context.Background()
	n := &recordingNotifier{}
	jm := NewJobManager(nil, newTestStore(t), nil, WithNotifier(n))

	ch := jm.CreateJobChannel(ctx, testAccount, testPeer)
	jm.JobQueued(ctx, testAccount, testPeer)
	jm.CloseChannel(ctx, testAccount, testPeer, ch)

	assert.Equal(t, []string{"opened", "queued", "closed"}, n.calls)
}

func TestSweeper_StopIsIdempotent(t *testing.T) {
	jm := NewJobManager(nil, newTestStore(t), nil)
	jm.StartSweeper()
	jm.StartSweeper()
	jm.Stop()
	jm.Stop()
}
