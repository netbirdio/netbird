package grpc

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	basegrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	rpproxy "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type playgroundSyncStream struct {
	basegrpc.ServerStream
	mu      sync.Mutex
	sent    []*proto.SyncMappingsResponse
	sendErr error
}

func (s *playgroundSyncStream) Send(message *proto.SyncMappingsResponse) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sendErr != nil {
		return s.sendErr
	}
	s.sent = append(s.sent, message)
	return nil
}

func (s *playgroundSyncStream) Recv() (*proto.SyncMappingsRequest, error) {
	return nil, context.Canceled
}

func (s *playgroundSyncStream) sentCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sent)
}

func (s *playgroundSyncStream) lastSent() *proto.SyncMappingsResponse {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sent) == 0 {
		return nil
	}
	return s.sent[len(s.sent)-1]
}

func TestExecuteAgentNetworkPlaygroundCorrelatesFrames(t *testing.T) {
	capable := true
	stream := &playgroundSyncStream{}
	connCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	conn := &proxyConnection{
		proxyID:         "proxy-a",
		capabilities:    &proto.ProxyCapabilities{SupportsAgentNetworkPlayground: &capable},
		syncStream:      stream,
		ctx:             connCtx,
		cancel:          cancel,
		pending:         make(map[string]*playgroundPending),
		playgroundReady: true,
	}
	server := &ProxyServiceServer{}
	server.connectedProxies.Store("proxy-a", conn)

	resultCh := make(chan *rpproxy.AgentNetworkPlaygroundResponse, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := server.ExecuteAgentNetworkPlayground(context.Background(), []string{"proxy-a"}, rpproxy.AgentNetworkPlaygroundRequest{
			PrincipalKind: rpproxy.PlaygroundPrincipalGroup,
			PrincipalID:   "group-1",
			RequestID:     "request-1",
			AccountID:     "account-1",
			GroupIDs:      []string{"group-1"},
			GroupNames:    []string{"Engineering"},
		})
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- result
	}()

	require.Eventually(t, func() bool { return stream.sentCount() == 1 }, time.Second, time.Millisecond, "Command should be sent")
	assert.True(t, conn.dispatchPlaygroundResponse(&proto.AgentNetworkPlaygroundResponse{
		RequestId:  "request-1",
		AccountId:  "account-1",
		StatusCode: 403,
	}))
	assert.True(t, conn.dispatchPlaygroundResponse(&proto.AgentNetworkPlaygroundResponse{
		RequestId: "request-1",
		AccountId: "account-1",
		BodyChunk: []byte("denied"),
	}))
	assert.True(t, conn.dispatchPlaygroundResponse(&proto.AgentNetworkPlaygroundResponse{
		RequestId:      "request-1",
		AccountId:      "account-1",
		Complete:       true,
		PolicyDecision: "deny",
		PolicyReason:   "no_authorised_provider",
	}))

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case result := <-resultCh:
		assert.Equal(t, 403, result.StatusCode, "Upstream denial should remain a normal result")
		assert.Equal(t, []byte("denied"), result.Body, "Body frames should be correlated and joined")
		assert.Equal(t, "deny", result.PolicyDecision, "Terminal metadata should be retained")
	case <-time.After(time.Second):
		t.Fatal("playground result did not complete")
	}
	assert.False(t, conn.dispatchPlaygroundResponse(&proto.AgentNetworkPlaygroundResponse{RequestId: "request-1"}), "Late frame should be discarded")
}

func TestExecuteAgentNetworkPlaygroundDoesNotRetryAfterSendFailure(t *testing.T) {
	capable := true
	firstStream := &playgroundSyncStream{sendErr: errors.New("uncertain send")}
	secondStream := &playgroundSyncStream{}
	server := &ProxyServiceServer{}
	for id, stream := range map[string]*playgroundSyncStream{"proxy-a": firstStream, "proxy-b": secondStream} {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		server.connectedProxies.Store(id, &proxyConnection{
			proxyID:         id,
			capabilities:    &proto.ProxyCapabilities{SupportsAgentNetworkPlayground: &capable},
			syncStream:      stream,
			ctx:             ctx,
			cancel:          cancel,
			pending:         make(map[string]*playgroundPending),
			playgroundReady: true,
		})
	}

	_, err := server.ExecuteAgentNetworkPlayground(context.Background(), []string{"proxy-a", "proxy-b"}, rpproxy.AgentNetworkPlaygroundRequest{
		PrincipalKind: rpproxy.PlaygroundPrincipalGroup,
		PrincipalID:   "group-1",
		RequestID:     "request-1",
		AccountID:     "account-1",
		GroupIDs:      []string{"group-1"},
		GroupNames:    []string{"Engineering"},
	})

	assert.Equal(t, codes.Unavailable, grpcstatus.Code(err), "Uncertain dispatch should return without retry")
	assert.Zero(t, secondStream.sentCount(), "Second replica must not receive a potentially double-billed request")
}

func TestExecuteAgentNetworkPlaygroundSendsCancellationAndClearsPending(t *testing.T) {
	capable := true
	stream := &playgroundSyncStream{}
	connCtx, connCancel := context.WithCancel(context.Background())
	t.Cleanup(connCancel)
	conn := &proxyConnection{
		proxyID:         "proxy-a",
		capabilities:    &proto.ProxyCapabilities{SupportsAgentNetworkPlayground: &capable},
		syncStream:      stream,
		ctx:             connCtx,
		cancel:          connCancel,
		pending:         make(map[string]*playgroundPending),
		playgroundReady: true,
	}
	server := &ProxyServiceServer{}
	server.connectedProxies.Store("proxy-a", conn)
	requestCtx, requestCancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		_, err := server.ExecuteAgentNetworkPlayground(requestCtx, []string{"proxy-a"}, rpproxy.AgentNetworkPlaygroundRequest{
			PrincipalKind: rpproxy.PlaygroundPrincipalGroup,
			PrincipalID:   "group-1",
			RequestID:     "request-1",
			AccountID:     "account-1",
			GroupIDs:      []string{"group-1"},
			GroupNames:    []string{"Engineering"},
		})
		errCh <- err
	}()

	require.Eventually(t, func() bool { return stream.sentCount() == 1 }, time.Second, time.Millisecond, "Command should be sent")
	requestCancel()
	assert.Equal(t, codes.Canceled, grpcstatus.Code(<-errCh), "Caller cancellation should propagate")
	require.Eventually(t, func() bool { return stream.sentCount() == 2 }, time.Second, time.Millisecond, "Cancellation should be sent")
	assert.Equal(t, "request-1", stream.lastSent().GetPlaygroundCancel().GetRequestId(), "Cancellation should correlate to the command")
	conn.pendingMu.Lock()
	pendingCount := len(conn.pending)
	conn.pendingMu.Unlock()
	assert.Zero(t, pendingCount, "Canceled request should be unregistered")
}

func TestAppendPlaygroundFrameRejectsBodyBeforeStart(t *testing.T) {
	result := &rpproxy.AgentNetworkPlaygroundResponse{RequestID: "request-1", AccountID: "account-1"}
	started := false
	_, err := appendPlaygroundFrame(result, &proto.AgentNetworkPlaygroundResponse{
		RequestId: "request-1",
		AccountId: "account-1",
		BodyChunk: []byte("unexpected"),
	}, &started)

	assert.ErrorContains(t, err, "before start")
}
