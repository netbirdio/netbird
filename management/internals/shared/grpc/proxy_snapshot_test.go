package grpc

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// recordingStream captures all messages sent via Send so tests can inspect
// batching behaviour without a real gRPC transport.
type recordingStream struct {
	grpc.ServerStream
	messages []*proto.GetMappingUpdateResponse
}

func (s *recordingStream) Send(m *proto.GetMappingUpdateResponse) error {
	s.messages = append(s.messages, m)
	return nil
}

func (s *recordingStream) Context() context.Context     { return context.Background() }
func (s *recordingStream) SetHeader(metadata.MD) error  { return nil }
func (s *recordingStream) SendHeader(metadata.MD) error { return nil }
func (s *recordingStream) SetTrailer(metadata.MD)       {}
func (s *recordingStream) SendMsg(any) error            { return nil }
func (s *recordingStream) RecvMsg(any) error            { return nil }

// makeServices creates n enabled services assigned to the given cluster.
func makeServices(n int, cluster string) []*rpservice.Service {
	services := make([]*rpservice.Service, n)
	for i := range n {
		services[i] = &rpservice.Service{
			ID:           fmt.Sprintf("svc-%d", i),
			AccountID:    "acct-1",
			Name:         fmt.Sprintf("svc-%d", i),
			Domain:       fmt.Sprintf("svc-%d.example.com", i),
			ProxyCluster: cluster,
			Enabled:      true,
			Targets: []*rpservice.Target{
				{TargetType: rpservice.TargetTypeHost, TargetId: "host-1"},
			},
		}
	}
	return services
}

func newSnapshotTestServer(t *testing.T, batchSize int) *ProxyServiceServer {
	t.Helper()
	s := &ProxyServiceServer{
		tokenStore:        NewOneTimeTokenStore(context.Background(), testCacheStore(t)),
		snapshotBatchSize: batchSize,
	}
	s.SetProxyController(newTestProxyController())
	return s
}

func TestSendSnapshot_BatchesMappings(t *testing.T) {
	const cluster = "cluster.example.com"
	const batchSize = 3
	const totalServices = 7 // 3 + 3 + 1

	ctrl := gomock.NewController(t)
	mgr := rpservice.NewMockManager(ctrl)
	mgr.EXPECT().GetGlobalServices(gomock.Any()).Return(makeServices(totalServices, cluster), nil)

	s := newSnapshotTestServer(t, batchSize)
	s.serviceManager = mgr

	stream := &recordingStream{}
	conn := &proxyConnection{
		proxyID: "proxy-a",
		address: cluster,
		stream:  stream,
	}

	err := s.sendSnapshot(context.Background(), conn)
	require.NoError(t, err)

	// Expect ceil(7/3) = 3 messages
	require.Len(t, stream.messages, 3, "should send ceil(totalServices/batchSize) messages")

	assert.Len(t, stream.messages[0].Mapping, 3)
	assert.False(t, stream.messages[0].InitialSyncComplete, "first batch should not be sync-complete")

	assert.Len(t, stream.messages[1].Mapping, 3)
	assert.False(t, stream.messages[1].InitialSyncComplete, "middle batch should not be sync-complete")

	assert.Len(t, stream.messages[2].Mapping, 1)
	assert.True(t, stream.messages[2].InitialSyncComplete, "last batch must be sync-complete")

	// Verify all service IDs are present exactly once
	seen := make(map[string]bool)
	for _, msg := range stream.messages {
		for _, m := range msg.Mapping {
			assert.False(t, seen[m.Id], "duplicate service ID %s", m.Id)
			seen[m.Id] = true
		}
	}
	assert.Len(t, seen, totalServices)
}

func TestSendSnapshot_ExactBatchMultiple(t *testing.T) {
	const cluster = "cluster.example.com"
	const batchSize = 3
	const totalServices = 6 // exactly 2 batches

	ctrl := gomock.NewController(t)
	mgr := rpservice.NewMockManager(ctrl)
	mgr.EXPECT().GetGlobalServices(gomock.Any()).Return(makeServices(totalServices, cluster), nil)

	s := newSnapshotTestServer(t, batchSize)
	s.serviceManager = mgr

	stream := &recordingStream{}
	conn := &proxyConnection{proxyID: "proxy-a", address: cluster, stream: stream}

	require.NoError(t, s.sendSnapshot(context.Background(), conn))
	require.Len(t, stream.messages, 2)

	assert.Len(t, stream.messages[0].Mapping, 3)
	assert.False(t, stream.messages[0].InitialSyncComplete)

	assert.Len(t, stream.messages[1].Mapping, 3)
	assert.True(t, stream.messages[1].InitialSyncComplete)
}

func TestSendSnapshot_SingleBatch(t *testing.T) {
	const cluster = "cluster.example.com"
	const batchSize = 100
	const totalServices = 5

	ctrl := gomock.NewController(t)
	mgr := rpservice.NewMockManager(ctrl)
	mgr.EXPECT().GetGlobalServices(gomock.Any()).Return(makeServices(totalServices, cluster), nil)

	s := newSnapshotTestServer(t, batchSize)
	s.serviceManager = mgr

	stream := &recordingStream{}
	conn := &proxyConnection{proxyID: "proxy-a", address: cluster, stream: stream}

	require.NoError(t, s.sendSnapshot(context.Background(), conn))
	require.Len(t, stream.messages, 1, "all mappings should fit in one batch")
	assert.Len(t, stream.messages[0].Mapping, totalServices)
	assert.True(t, stream.messages[0].InitialSyncComplete)
}

func TestSendSnapshot_EmptySnapshot(t *testing.T) {
	const cluster = "cluster.example.com"

	ctrl := gomock.NewController(t)
	mgr := rpservice.NewMockManager(ctrl)
	mgr.EXPECT().GetGlobalServices(gomock.Any()).Return(nil, nil)

	s := newSnapshotTestServer(t, 500)
	s.serviceManager = mgr

	stream := &recordingStream{}
	conn := &proxyConnection{proxyID: "proxy-a", address: cluster, stream: stream}

	require.NoError(t, s.sendSnapshot(context.Background(), conn))
	require.Len(t, stream.messages, 1, "empty snapshot must still send sync-complete")
	assert.Empty(t, stream.messages[0].Mapping)
	assert.True(t, stream.messages[0].InitialSyncComplete)
}
