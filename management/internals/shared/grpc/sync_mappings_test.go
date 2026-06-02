package grpc

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// syncRecordingStream is a mock ProxyService_SyncMappingsServer that records
// sent messages and returns pre-loaded ack responses from Recv.
type syncRecordingStream struct {
	grpc.ServerStream

	mu       sync.Mutex
	sent     []*proto.SyncMappingsResponse
	recvMsgs []*proto.SyncMappingsRequest
	recvIdx  int
}

func (s *syncRecordingStream) Send(m *proto.SyncMappingsResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, m)
	return nil
}

func (s *syncRecordingStream) Recv() (*proto.SyncMappingsRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recvIdx >= len(s.recvMsgs) {
		return nil, fmt.Errorf("no more recv messages")
	}
	msg := s.recvMsgs[s.recvIdx]
	s.recvIdx++
	return msg, nil
}

func (s *syncRecordingStream) Context() context.Context     { return context.Background() }
func (s *syncRecordingStream) SetHeader(metadata.MD) error  { return nil }
func (s *syncRecordingStream) SendHeader(metadata.MD) error { return nil }
func (s *syncRecordingStream) SetTrailer(metadata.MD)       {}
func (s *syncRecordingStream) SendMsg(any) error            { return nil }
func (s *syncRecordingStream) RecvMsg(any) error            { return nil }

func ackMsg() *proto.SyncMappingsRequest {
	return &proto.SyncMappingsRequest{
		Msg: &proto.SyncMappingsRequest_Ack{Ack: &proto.SyncMappingsAck{}},
	}
}

func TestSendSnapshotSync_BatchesWithAcks(t *testing.T) {
	const cluster = "cluster.example.com"
	const batchSize = 3
	const totalServices = 7 // 3 + 3 + 1 → 3 batches, 3 acks (one per batch, including final)

	ctrl := gomock.NewController(t)
	mgr := rpservice.NewMockManager(ctrl)
	mgr.EXPECT().GetGlobalServices(gomock.Any()).Return(makeServices(totalServices, cluster), nil)

	s := newSnapshotTestServer(t, batchSize)
	s.serviceManager = mgr

	stream := &syncRecordingStream{
		recvMsgs: []*proto.SyncMappingsRequest{ackMsg(), ackMsg(), ackMsg()},
	}
	conn := &proxyConnection{
		proxyID:    "proxy-a",
		address:    cluster,
		syncStream: stream,
	}

	err := s.sendSnapshotSync(context.Background(), conn, stream)
	require.NoError(t, err)

	require.Len(t, stream.sent, 3, "should send ceil(7/3) = 3 batches")

	assert.Len(t, stream.sent[0].Mapping, 3)
	assert.False(t, stream.sent[0].InitialSyncComplete)

	assert.Len(t, stream.sent[1].Mapping, 3)
	assert.False(t, stream.sent[1].InitialSyncComplete)

	assert.Len(t, stream.sent[2].Mapping, 1)
	assert.True(t, stream.sent[2].InitialSyncComplete)

	// All 3 acks consumed — including the final batch.
	assert.Equal(t, 3, stream.recvIdx)
}

func TestSendSnapshotSync_SingleBatchWaitsForAck(t *testing.T) {
	const cluster = "cluster.example.com"
	const batchSize = 100
	const totalServices = 5

	ctrl := gomock.NewController(t)
	mgr := rpservice.NewMockManager(ctrl)
	mgr.EXPECT().GetGlobalServices(gomock.Any()).Return(makeServices(totalServices, cluster), nil)

	s := newSnapshotTestServer(t, batchSize)
	s.serviceManager = mgr

	stream := &syncRecordingStream{
		recvMsgs: []*proto.SyncMappingsRequest{ackMsg()},
	}
	conn := &proxyConnection{
		proxyID:    "proxy-a",
		address:    cluster,
		syncStream: stream,
	}

	err := s.sendSnapshotSync(context.Background(), conn, stream)
	require.NoError(t, err)

	require.Len(t, stream.sent, 1)
	assert.Len(t, stream.sent[0].Mapping, totalServices)
	assert.True(t, stream.sent[0].InitialSyncComplete)
	assert.Equal(t, 1, stream.recvIdx, "final batch ack must be consumed")
}

func TestSendSnapshotSync_EmptySnapshot(t *testing.T) {
	const cluster = "cluster.example.com"

	ctrl := gomock.NewController(t)
	mgr := rpservice.NewMockManager(ctrl)
	mgr.EXPECT().GetGlobalServices(gomock.Any()).Return(nil, nil)

	s := newSnapshotTestServer(t, 500)
	s.serviceManager = mgr

	stream := &syncRecordingStream{
		recvMsgs: []*proto.SyncMappingsRequest{ackMsg()},
	}
	conn := &proxyConnection{
		proxyID:    "proxy-a",
		address:    cluster,
		syncStream: stream,
	}

	err := s.sendSnapshotSync(context.Background(), conn, stream)
	require.NoError(t, err)

	require.Len(t, stream.sent, 1, "empty snapshot must still send sync-complete")
	assert.Empty(t, stream.sent[0].Mapping)
	assert.True(t, stream.sent[0].InitialSyncComplete)
	assert.Equal(t, 1, stream.recvIdx, "empty snapshot ack must be consumed")
}

func TestSendSnapshotSync_MissingAckReturnsError(t *testing.T) {
	const cluster = "cluster.example.com"
	const batchSize = 2
	const totalServices = 4 // 2 batches → 1 ack needed, but we provide none

	ctrl := gomock.NewController(t)
	mgr := rpservice.NewMockManager(ctrl)
	mgr.EXPECT().GetGlobalServices(gomock.Any()).Return(makeServices(totalServices, cluster), nil)

	s := newSnapshotTestServer(t, batchSize)
	s.serviceManager = mgr

	// No acks available — Recv will return error.
	stream := &syncRecordingStream{}
	conn := &proxyConnection{
		proxyID:    "proxy-a",
		address:    cluster,
		syncStream: stream,
	}

	err := s.sendSnapshotSync(context.Background(), conn, stream)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "receive ack")
	// First batch should have been sent before the error.
	require.Len(t, stream.sent, 1)
}

func TestSendSnapshotSync_WrongMessageInsteadOfAck(t *testing.T) {
	const cluster = "cluster.example.com"
	const batchSize = 2
	const totalServices = 4

	ctrl := gomock.NewController(t)
	mgr := rpservice.NewMockManager(ctrl)
	mgr.EXPECT().GetGlobalServices(gomock.Any()).Return(makeServices(totalServices, cluster), nil)

	s := newSnapshotTestServer(t, batchSize)
	s.serviceManager = mgr

	// Send an init message instead of an ack.
	stream := &syncRecordingStream{
		recvMsgs: []*proto.SyncMappingsRequest{
			{Msg: &proto.SyncMappingsRequest_Init{Init: &proto.SyncMappingsInit{ProxyId: "bad"}}},
		},
	}
	conn := &proxyConnection{
		proxyID:    "proxy-a",
		address:    cluster,
		syncStream: stream,
	}

	err := s.sendSnapshotSync(context.Background(), conn, stream)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected ack")
}

func TestSendSnapshotSync_BackPressureOrdering(t *testing.T) {
	// Verify batches are sent strictly sequentially — batch N+1 is not sent
	// until the ack for batch N is received, including the final batch.
	const cluster = "cluster.example.com"
	const batchSize = 2
	const totalServices = 6 // 3 batches, 3 acks

	ctrl := gomock.NewController(t)
	mgr := rpservice.NewMockManager(ctrl)
	mgr.EXPECT().GetGlobalServices(gomock.Any()).Return(makeServices(totalServices, cluster), nil)

	s := newSnapshotTestServer(t, batchSize)
	s.serviceManager = mgr

	var mu sync.Mutex
	var events []string

	// Build a stream that logs send/recv events so we can verify ordering.
	ackCh := make(chan struct{}, 3)
	stream := &orderTrackingStream{
		mu:     &mu,
		events: &events,
		ackCh:  ackCh,
	}
	conn := &proxyConnection{
		proxyID:    "proxy-a",
		address:    cluster,
		syncStream: stream,
	}

	// Feed acks asynchronously after a short delay to simulate real proxy.
	go func() {
		for range 3 {
			time.Sleep(10 * time.Millisecond)
			ackCh <- struct{}{}
		}
	}()

	err := s.sendSnapshotSync(context.Background(), conn, stream)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()

	// Expected: send, recv-ack, send, recv-ack, send, recv-ack.
	require.Len(t, events, 6)
	assert.Equal(t, "send", events[0])
	assert.Equal(t, "recv", events[1])
	assert.Equal(t, "send", events[2])
	assert.Equal(t, "recv", events[3])
	assert.Equal(t, "send", events[4])
	assert.Equal(t, "recv", events[5])
}

// orderTrackingStream logs "send" and "recv" events and blocks Recv until
// an ack is signaled via ackCh.
type orderTrackingStream struct {
	grpc.ServerStream
	mu     *sync.Mutex
	events *[]string
	ackCh  chan struct{}
}

func (s *orderTrackingStream) Send(_ *proto.SyncMappingsResponse) error {
	s.mu.Lock()
	*s.events = append(*s.events, "send")
	s.mu.Unlock()
	return nil
}

func (s *orderTrackingStream) Recv() (*proto.SyncMappingsRequest, error) {
	<-s.ackCh
	s.mu.Lock()
	*s.events = append(*s.events, "recv")
	s.mu.Unlock()
	return ackMsg(), nil
}

func (s *orderTrackingStream) Context() context.Context     { return context.Background() }
func (s *orderTrackingStream) SetHeader(metadata.MD) error  { return nil }
func (s *orderTrackingStream) SendHeader(metadata.MD) error { return nil }
func (s *orderTrackingStream) SetTrailer(metadata.MD)       {}
func (s *orderTrackingStream) SendMsg(any) error            { return nil }
func (s *orderTrackingStream) RecvMsg(any) error            { return nil }

func TestSendSnapshotSync_TokensGeneratedPerBatch(t *testing.T) {
	const cluster = "cluster.example.com"
	const batchSize = 2
	const totalServices = 4
	const ttl = 100 * time.Millisecond
	const ackDelay = 200 * time.Millisecond

	ctrl := gomock.NewController(t)
	mgr := rpservice.NewMockManager(ctrl)
	mgr.EXPECT().GetGlobalServices(gomock.Any()).Return(makeServices(totalServices, cluster), nil)

	s := newSnapshotTestServer(t, batchSize)
	s.serviceManager = mgr
	s.tokenTTL = ttl

	// Build a stream that validates tokens immediately on Send, then
	// delays the ack to ensure the next batch's tokens are generated fresh.
	var validateErrs []error
	ackCh := make(chan struct{}, 2)
	stream := &tokenValidatingSyncStream{
		tokenStore:   s.tokenStore,
		validateErrs: &validateErrs,
		ackCh:        ackCh,
	}
	conn := &proxyConnection{
		proxyID:    "proxy-a",
		address:    cluster,
		syncStream: stream,
	}

	go func() {
		// Delay first ack so that if tokens were all generated upfront they'd expire.
		time.Sleep(ackDelay)
		ackCh <- struct{}{}
		// Final batch ack — immediate.
		ackCh <- struct{}{}
	}()

	err := s.sendSnapshotSync(context.Background(), conn, stream)
	require.NoError(t, err)
	require.Empty(t, validateErrs,
		"tokens must remain valid: per-batch generation guarantees freshness")
}

type tokenValidatingSyncStream struct {
	grpc.ServerStream
	tokenStore   *OneTimeTokenStore
	validateErrs *[]error
	ackCh        chan struct{}
}

func (s *tokenValidatingSyncStream) Send(m *proto.SyncMappingsResponse) error {
	for _, mapping := range m.Mapping {
		if err := s.tokenStore.ValidateAndConsume(mapping.AuthToken, mapping.AccountId, mapping.Id); err != nil {
			*s.validateErrs = append(*s.validateErrs, fmt.Errorf("svc %s: %w", mapping.Id, err))
		}
	}
	return nil
}

func (s *tokenValidatingSyncStream) Recv() (*proto.SyncMappingsRequest, error) {
	<-s.ackCh
	return ackMsg(), nil
}

func (s *tokenValidatingSyncStream) Context() context.Context     { return context.Background() }
func (s *tokenValidatingSyncStream) SetHeader(metadata.MD) error  { return nil }
func (s *tokenValidatingSyncStream) SendHeader(metadata.MD) error { return nil }
func (s *tokenValidatingSyncStream) SetTrailer(metadata.MD)       {}
func (s *tokenValidatingSyncStream) SendMsg(any) error            { return nil }
func (s *tokenValidatingSyncStream) RecvMsg(any) error            { return nil }

func TestConnectionSendResponse_RoutesToSyncStream(t *testing.T) {
	stream := &syncRecordingStream{}
	conn := &proxyConnection{
		syncStream: stream,
	}

	resp := &proto.GetMappingUpdateResponse{
		Mapping: []*proto.ProxyMapping{
			{Id: "svc-1", AccountId: "acct-1", Domain: "example.com"},
		},
		InitialSyncComplete: true,
	}

	err := conn.sendResponse(resp)
	require.NoError(t, err)

	require.Len(t, stream.sent, 1)
	assert.Len(t, stream.sent[0].Mapping, 1)
	assert.Equal(t, "svc-1", stream.sent[0].Mapping[0].Id)
	assert.True(t, stream.sent[0].InitialSyncComplete)
}

func TestConnectionSendResponse_RoutesToLegacyStream(t *testing.T) {
	stream := &recordingStream{}
	conn := &proxyConnection{
		stream: stream,
	}

	resp := &proto.GetMappingUpdateResponse{
		Mapping: []*proto.ProxyMapping{
			{Id: "svc-2", AccountId: "acct-2"},
		},
	}

	err := conn.sendResponse(resp)
	require.NoError(t, err)

	require.Len(t, stream.messages, 1)
	assert.Equal(t, "svc-2", stream.messages[0].Mapping[0].Id)
}
