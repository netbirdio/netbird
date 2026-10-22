package server

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbjob "github.com/netbirdio/netbird/management/server/job"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

func setupPeerJobTest(t *testing.T, connected bool) (*DefaultAccountManager, string, string) {
	t.Helper()
	ctx := context.Background()

	manager, _, err := createManager(t)
	require.NoError(t, err)
	account, err := createAccount(manager, "job_test", userID, "")
	require.NoError(t, err)
	setupKey, err := manager.CreateSetupKey(ctx, account.Id, "job-key", types.SetupKeyReusable, time.Hour, nil, 10, userID, false, false)
	require.NoError(t, err)

	peer := addPeerToAccount(t, manager, account.Id, setupKey.Key)
	peer, err = manager.Store.GetPeerByID(ctx, store.LockingStrengthNone, account.Id, peer.ID)
	require.NoError(t, err)
	peer.Meta.WtVersion = "0.70.0"
	require.NoError(t, manager.Store.SavePeer(ctx, account.Id, peer))
	require.NoError(t, manager.Store.SavePeerStatus(ctx, account.Id, peer.ID, nbpeer.PeerStatus{Connected: connected, LastSeen: time.Now().UTC()}))

	return manager, account.Id, peer.ID
}

func newBundleJob(t *testing.T, accountID, peerID string) *types.Job {
	t.Helper()
	params, err := json.Marshal(api.BundleParameters{LogFileCount: 1})
	require.NoError(t, err)
	return &types.Job{
		ID:          uuid.New().String(),
		TriggeredBy: userID,
		AccountID:   accountID,
		PeerID:      peerID,
		Status:      types.JobStatusPending,
		CreatedAt:   time.Now().UTC(),
		Workload:    types.Workload{Type: types.JobTypeBundle, Parameters: params},
	}
}

func TestCreatePeerJob_RefusesOfflinePeer(t *testing.T) {
	manager, accountID, peerID := setupPeerJobTest(t, false)

	err := manager.CreatePeerJob(context.Background(), accountID, peerID, userID, newBundleJob(t, accountID, peerID))
	assert.ErrorContains(t, err, "peer not connected")
}

// The node that serves the API does not hold the peer's job stream, so the job is
// persisted with a deadline and waits to be sent, instead of failing.
func TestCreatePeerJob_QueuesWithoutLocalStream(t *testing.T) {
	ctx := context.Background()
	manager, accountID, peerID := setupPeerJobTest(t, true)

	job := newBundleJob(t, accountID, peerID)
	require.NoError(t, manager.CreatePeerJob(ctx, accountID, peerID, userID, job))

	stored, err := manager.Store.GetPeerJobByID(ctx, accountID, peerID, job.ID)
	require.NoError(t, err)
	assert.Equal(t, types.JobStatusPending, stored.Status)
	assert.Nil(t, stored.DispatchedAt, "no stream on this node, so the job stays queued")
	require.NotNil(t, stored.DeadlineAt)
	assert.WithinDuration(t, time.Now().Add(nbjob.QueuedTimeout), *stored.DeadlineAt, 5*time.Second, "a queued job should get the queued deadline")

	err = manager.CreatePeerJob(ctx, accountID, peerID, userID, newBundleJob(t, accountID, peerID))
	assert.ErrorContains(t, err, "already has pending job", "a peer runs one job at a time")
}

func TestCreatePeerJob_ConcurrentCreatesOneWins(t *testing.T) {
	manager, accountID, peerID := setupPeerJobTest(t, true)

	var wg sync.WaitGroup
	var mu sync.Mutex
	created := 0
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := manager.CreatePeerJob(context.Background(), accountID, peerID, userID, newBundleJob(t, accountID, peerID)); err != nil {
				return
			}
			mu.Lock()
			created++
			mu.Unlock()
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, created, "only one of the concurrent creates should succeed")
	jobs, err := manager.Store.GetPeerJobs(context.Background(), accountID, peerID)
	require.NoError(t, err)
	assert.Len(t, jobs, 1, "only one job should be stored")
}
