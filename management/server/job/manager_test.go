package job

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/netbirdio/netbird/management/server/store"
)

func TestCloseChannel_OwnSession(t *testing.T) {
	ctx := context.Background()
	mockStore := store.NewMockStore(gomock.NewController(t))
	jm := NewJobManager(nil, mockStore, nil)

	session := NewChannel()
	jm.jobChannels["peer-1"] = session
	jm.pending["job-1"] = &Event{PeerID: "peer-1"}
	jm.pending["job-2"] = &Event{PeerID: "peer-2"}

	mockStore.EXPECT().MarkPendingJobsAsFailed(gomock.Any(), "account-1", "peer-1", "job-1", gomock.Any()).Return(nil)

	jm.CloseChannel(ctx, "account-1", "peer-1", session)

	assert.False(t, jm.IsPeerConnected("peer-1"))
	_, err := session.Event(ctx)
	assert.ErrorIs(t, err, ErrJobChannelClosed)
	assert.NotContains(t, jm.pending, "job-1")
	assert.Contains(t, jm.pending, "job-2", "jobs of other peers must be kept")
}

func TestCloseChannel_NewerSessionOwnsPeer(t *testing.T) {
	ctx := context.Background()
	jm := NewJobManager(nil, store.NewMockStore(gomock.NewController(t)), nil)

	stale := NewChannel()
	current := NewChannel()
	jm.jobChannels["peer-1"] = current
	jm.pending["job-1"] = &Event{PeerID: "peer-1"}

	jm.CloseChannel(ctx, "account-1", "peer-1", stale)

	require.True(t, jm.IsPeerConnected("peer-1"))
	assert.Contains(t, jm.pending, "job-1", "jobs served by the newer stream must not be failed")

	event := &Event{PeerID: "peer-1"}
	require.NoError(t, current.AddEvent(ctx, time.Second, event))
	got, err := current.Event(ctx)
	require.NoError(t, err, "newer session channel must stay open")
	assert.Equal(t, event, got)
}

func TestCreateJobChannel_ReplacesSessionAndDropsItsPendingJobs(t *testing.T) {
	ctx := context.Background()
	mockStore := store.NewMockStore(gomock.NewController(t))
	jm := NewJobManager(nil, mockStore, nil)

	stale := NewChannel()
	jm.jobChannels["peer-1"] = stale
	jm.pending["job-1"] = &Event{PeerID: "peer-1"}
	jm.pending["job-2"] = &Event{PeerID: "peer-2"}

	mockStore.EXPECT().MarkAllPendingJobsAsFailed(gomock.Any(), "account-1", "peer-1", gomock.Any()).Return(nil)
	mockStore.EXPECT().MarkPendingJobsAsFailed(gomock.Any(), "account-1", "peer-1", "job-1", "Pending job cleanup: job stream replaced by a newer stream").Return(nil)

	current := jm.CreateJobChannel(ctx, "account-1", "peer-1")

	require.NotSame(t, stale, current)
	_, err := stale.Event(ctx)
	assert.ErrorIs(t, err, ErrJobChannelClosed, "replaced channel must be closed")
	assert.True(t, jm.IsPeerConnected("peer-1"))
	assert.False(t, jm.IsPeerHasPendingJobs("peer-1"), "jobs of the replaced stream must be dropped")
	assert.Contains(t, jm.pending, "job-2", "jobs of other peers must be kept")
}
