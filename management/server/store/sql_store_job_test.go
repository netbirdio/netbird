package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/types"
)

const (
	jobTestAccount = "job-account"
	jobTestPeer    = "job-peer"
)

func newJobTestStore(t *testing.T) Store {
	t.Helper()
	s, cleanup, err := NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)
	return s
}

func insertJob(t *testing.T, s Store, id, peerID string, createdAt time.Time, deadline *time.Time) {
	t.Helper()
	require.NoError(t, s.CreatePeerJob(context.Background(), &types.Job{
		ID:         id,
		AccountID:  jobTestAccount,
		PeerID:     peerID,
		Status:     types.JobStatusPending,
		CreatedAt:  createdAt,
		DeadlineAt: deadline,
		Workload:   types.Workload{Type: types.JobTypeBundle, Parameters: []byte("{}")},
	}))
}

func timePtr(t time.Time) *time.Time { return &t }

func getJob(t *testing.T, s Store, peerID, id string) *types.Job {
	t.Helper()
	job, err := s.GetPeerJobByID(context.Background(), jobTestAccount, peerID, id)
	require.NoError(t, err)
	return job
}

func TestClaimPeerJob_OnlyOnce(t *testing.T) {
	s := newJobTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	insertJob(t, s, "job-1", jobTestPeer, now, timePtr(now.Add(time.Minute)))

	queued, err := s.GetQueuedPeerJobs(ctx, jobTestAccount, jobTestPeer)
	require.NoError(t, err)
	require.Len(t, queued, 1, "a new job is queued")

	claimed, err := s.ClaimPeerJob(ctx, jobTestAccount, jobTestPeer, "job-1", now, now.Add(10*time.Minute))
	require.NoError(t, err)
	assert.True(t, claimed, "the first claim should win")

	claimed, err = s.ClaimPeerJob(ctx, jobTestAccount, jobTestPeer, "job-1", now, now.Add(10*time.Minute))
	require.NoError(t, err)
	assert.False(t, claimed, "a dispatched job must not be claimed again")

	queued, err = s.GetQueuedPeerJobs(ctx, jobTestAccount, jobTestPeer)
	require.NoError(t, err)
	assert.Empty(t, queued, "a dispatched job is no longer queued")

	job := getJob(t, s, jobTestPeer, "job-1")
	require.NotNil(t, job.DeadlineAt)
	assert.WithinDuration(t, now.Add(10*time.Minute), *job.DeadlineAt, time.Second, "the claim should move the deadline to the run timeout")
}

func TestClaimPeerJob_ConcurrentNodesWinOnce(t *testing.T) {
	s := newJobTestStore(t)
	now := time.Now().UTC()
	insertJob(t, s, "job-1", jobTestPeer, now, timePtr(now.Add(time.Minute)))

	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			claimed, err := s.ClaimPeerJob(context.Background(), jobTestAccount, jobTestPeer, "job-1", now, now.Add(time.Minute))
			if err != nil || !claimed {
				return
			}
			mu.Lock()
			wins++
			mu.Unlock()
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, wins, "exactly one node should send the job")
}

func TestCompleteDispatchedPeerJob_OnlyRunningJobOfThatPeer(t *testing.T) {
	s := newJobTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	insertJob(t, s, "job-1", jobTestPeer, now, timePtr(now.Add(time.Minute)))

	answer := &types.Job{ID: "job-1", Status: types.JobStatusSucceeded, CompletedAt: &now}

	completed, err := s.CompleteDispatchedPeerJob(ctx, jobTestAccount, jobTestPeer, answer)
	require.NoError(t, err)
	assert.False(t, completed, "an answer to a job that was never sent must be dropped")

	_, err = s.ClaimPeerJob(ctx, jobTestAccount, jobTestPeer, "job-1", now, now.Add(time.Minute))
	require.NoError(t, err)

	completed, err = s.CompleteDispatchedPeerJob(ctx, jobTestAccount, "other-peer", answer)
	require.NoError(t, err)
	assert.False(t, completed, "another peer must not finish this peer's job")

	completed, err = s.CompleteDispatchedPeerJob(ctx, jobTestAccount, jobTestPeer, answer)
	require.NoError(t, err)
	assert.True(t, completed, "the peer's answer should finish its running job")

	completed, err = s.CompleteDispatchedPeerJob(ctx, jobTestAccount, jobTestPeer, answer)
	require.NoError(t, err)
	assert.False(t, completed, "a duplicate answer must be dropped")

	assert.Equal(t, types.JobStatusSucceeded, getJob(t, s, jobTestPeer, "job-1").Status)
}

func TestFailDispatchedPeerJobs_KeepsQueued(t *testing.T) {
	s := newJobTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	insertJob(t, s, "running", jobTestPeer, now, timePtr(now.Add(time.Minute)))
	insertJob(t, s, "queued", jobTestPeer, now.Add(time.Second), timePtr(now.Add(time.Minute)))
	_, err := s.ClaimPeerJob(ctx, jobTestAccount, jobTestPeer, "running", now, now.Add(time.Minute))
	require.NoError(t, err)

	require.NoError(t, s.FailDispatchedPeerJobs(ctx, jobTestAccount, jobTestPeer, "reconnected"))

	running := getJob(t, s, jobTestPeer, "running")
	assert.Equal(t, types.JobStatusFailed, running.Status, "a job sent on the old stream should fail")
	assert.Equal(t, "reconnected", running.FailedReason)
	assert.Equal(t, types.JobStatusPending, getJob(t, s, jobTestPeer, "queued").Status, "a queued job should wait for the new stream")
}

func TestFailExpiredPeerJobs_ReasonPerStage(t *testing.T) {
	s := newJobTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	insertJob(t, s, "queued-expired", jobTestPeer, now.Add(-3*time.Minute), timePtr(now.Add(-time.Minute)))
	insertJob(t, s, "queued-live", "peer-2", now, timePtr(now.Add(time.Minute)))
	insertJob(t, s, "dispatched-expired", "peer-3", now.Add(-20*time.Minute), timePtr(now.Add(-time.Hour)))
	_, err := s.ClaimPeerJob(ctx, jobTestAccount, "peer-3", "dispatched-expired", now.Add(-15*time.Minute), now.Add(-5*time.Minute))
	require.NoError(t, err)
	// Rows written before deadlines existed have none.
	insertJob(t, s, "legacy-old", "peer-4", now.Add(-time.Hour), nil)
	insertJob(t, s, "legacy-recent", "peer-5", now.Add(-time.Minute), nil)

	failed, err := s.FailExpiredPeerJobs(ctx, now, now.Add(-10*time.Minute), "not picked up", "no response")
	require.NoError(t, err)
	assert.Equal(t, int64(3), failed, "the expired queued, dispatched and old legacy jobs should fail")

	assert.Equal(t, "not picked up", getJob(t, s, jobTestPeer, "queued-expired").FailedReason)
	assert.Equal(t, "no response", getJob(t, s, "peer-3", "dispatched-expired").FailedReason)
	assert.Equal(t, "not picked up", getJob(t, s, "peer-4", "legacy-old").FailedReason)
	assert.Equal(t, types.JobStatusPending, getJob(t, s, "peer-2", "queued-live").Status, "a job before its deadline stays pending")
	assert.Equal(t, types.JobStatusPending, getJob(t, s, "peer-5", "legacy-recent").Status, "a recent legacy job stays pending")
}

func TestHasPendingPeerJob(t *testing.T) {
	s := newJobTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	pending, err := s.HasPendingPeerJob(ctx, jobTestAccount, jobTestPeer)
	require.NoError(t, err)
	assert.False(t, pending, "a peer without jobs has none pending")

	insertJob(t, s, "job-1", jobTestPeer, now, timePtr(now.Add(time.Minute)))
	pending, err = s.HasPendingPeerJob(ctx, jobTestAccount, jobTestPeer)
	require.NoError(t, err)
	assert.True(t, pending, "a queued job is pending")

	require.NoError(t, s.FailDispatchedPeerJobs(ctx, jobTestAccount, jobTestPeer, "x"))
	_, err = s.FailExpiredPeerJobs(ctx, now.Add(time.Hour), now, "expired", "expired")
	require.NoError(t, err)
	pending, err = s.HasPendingPeerJob(ctx, jobTestAccount, jobTestPeer)
	require.NoError(t, err)
	assert.False(t, pending, "a failed job is no longer pending")
}

func TestGetPeerJobByID_FiltersByPeer(t *testing.T) {
	s := newJobTestStore(t)
	now := time.Now().UTC()
	insertJob(t, s, "job-1", jobTestPeer, now, timePtr(now.Add(time.Minute)))

	_, err := s.GetPeerJobByID(context.Background(), jobTestAccount, "other-peer", "job-1")
	assert.Error(t, err, "a job must not be readable through another peer")
}

// A pending job from before the upgrade was already sent by the node that created it;
// sending it again would run it twice.
func TestGetQueuedPeerJobs_SkipsLegacyJobs(t *testing.T) {
	s := newJobTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	insertJob(t, s, "legacy", jobTestPeer, now, nil)

	queued, err := s.GetQueuedPeerJobs(ctx, jobTestAccount, jobTestPeer)
	require.NoError(t, err)
	assert.Empty(t, queued, "a job without a deadline must not be sent again")

	claimed, err := s.ClaimPeerJob(ctx, jobTestAccount, jobTestPeer, "legacy", now, now.Add(time.Minute))
	require.NoError(t, err)
	assert.False(t, claimed, "a job without a deadline must not be claimed")

	pending, err := s.HasPendingPeerJob(ctx, jobTestAccount, jobTestPeer)
	require.NoError(t, err)
	assert.True(t, pending, "it still blocks a new job until the sweeper fails it")
}
