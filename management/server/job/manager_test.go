package job

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func newTestManager(t *testing.T) (*Manager, *store.MockStore) {
	t.Helper()
	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)
	mockStore := store.NewMockStore(ctrl)
	return NewJobManager(nil, mockStore, nil), mockStore
}

func TestSendJobDeliversThroughRegisteredStream(t *testing.T) {
	ctx := context.Background()
	manager, mockStore := newTestManager(t)
	mockStore.EXPECT().MarkAllPendingJobsAsFailed(gomock.Any(), "acc", "peer1", gomock.Any()).Return(nil)

	var sent []*Event
	manager.RegisterStream(ctx, "acc", "peer1", func(event *Event) error {
		sent = append(sent, event)
		return nil
	})
	require.True(t, manager.IsPeerConnected("peer1"))

	err := manager.SendJob(ctx, "acc", "peer1", &proto.JobRequest{ID: []byte("job1")})
	require.NoError(t, err)
	require.Len(t, sent, 1)
	require.Equal(t, "peer1", sent[0].PeerID)
	require.True(t, manager.IsPeerHasPendingJobs("peer1"))
}

func TestSendJobWithoutStream(t *testing.T) {
	manager, _ := newTestManager(t)
	err := manager.SendJob(context.Background(), "acc", "peer1", &proto.JobRequest{ID: []byte("job1")})
	require.Error(t, err)
}

func TestSendJobFailureCleansPending(t *testing.T) {
	ctx := context.Background()
	manager, mockStore := newTestManager(t)
	mockStore.EXPECT().MarkAllPendingJobsAsFailed(gomock.Any(), "acc", "peer1", gomock.Any()).Return(nil)
	mockStore.EXPECT().MarkPendingJobsAsFailed(gomock.Any(), "acc", "peer1", "job1", gomock.Any()).Return(nil)

	manager.RegisterStream(ctx, "acc", "peer1", func(*Event) error {
		return errors.New("stream broken")
	})

	err := manager.SendJob(ctx, "acc", "peer1", &proto.JobRequest{ID: []byte("job1")})
	require.Error(t, err)
	require.False(t, manager.IsPeerHasPendingJobs("peer1"))
}

func TestUnregisterStreamIgnoresSupersededRegistration(t *testing.T) {
	ctx := context.Background()
	manager, mockStore := newTestManager(t)
	mockStore.EXPECT().MarkAllPendingJobsAsFailed(gomock.Any(), "acc", "peer1", gomock.Any()).Return(nil).Times(2)

	first := manager.RegisterStream(ctx, "acc", "peer1", func(*Event) error { return nil })
	second := manager.RegisterStream(ctx, "acc", "peer1", func(*Event) error { return nil })

	manager.UnregisterStream(ctx, "acc", "peer1", first)
	require.True(t, manager.IsPeerConnected("peer1"), "stale unregister must not remove the replacement stream")

	manager.UnregisterStream(ctx, "acc", "peer1", second)
	require.False(t, manager.IsPeerConnected("peer1"))
}

func TestUnregisterStreamFailsPendingJobs(t *testing.T) {
	ctx := context.Background()
	manager, mockStore := newTestManager(t)
	mockStore.EXPECT().MarkAllPendingJobsAsFailed(gomock.Any(), "acc", "peer1", gomock.Any()).Return(nil)
	mockStore.EXPECT().MarkPendingJobsAsFailed(gomock.Any(), "acc", "peer1", "job1", gomock.Any()).Return(nil)

	stream := manager.RegisterStream(ctx, "acc", "peer1", func(*Event) error { return nil })
	require.NoError(t, manager.SendJob(ctx, "acc", "peer1", &proto.JobRequest{ID: []byte("job1")}))
	require.True(t, manager.IsPeerHasPendingJobs("peer1"))

	manager.UnregisterStream(ctx, "acc", "peer1", stream)
	require.False(t, manager.IsPeerHasPendingJobs("peer1"))
}
