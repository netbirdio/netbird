package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rpproxy "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/proxy"
	"github.com/netbirdio/netbird/shared/management/proto"
	nbstatus "github.com/netbirdio/netbird/shared/management/status"
)

type modelDiscoveryCall struct {
	result *proto.ModelDiscoveryResult
	err    error
}

func newModelDiscoveryTestServer(t *testing.T) (*ProxyServiceServer, *testProxyController) {
	t.Helper()
	controller := newTestProxyController()
	server := &ProxyServiceServer{
		proxyController:       controller,
		modelDiscoveryPending: make(map[string]*pendingModelDiscovery),
	}
	return server, controller
}

func addModelDiscoveryTestConnection(
	t *testing.T,
	server *ProxyServiceServer,
	controller *testProxyController,
	proxyID, sessionID, cluster string,
	accountID *string,
	supportsDiscovery bool,
) (*proxyConnection, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	close(ready)
	conn := &proxyConnection{
		proxyID:   proxyID,
		sessionID: sessionID,
		address:   cluster,
		accountID: accountID,
		capabilities: &proto.ProxyCapabilities{
			SupportsModelDiscovery: &supportsDiscovery,
		},
		syncStream:         &syncRecordingStream{},
		modelDiscoveryChan: make(chan *proto.ModelDiscoveryRequest, modelDiscoveryQueueSize),
		ready:              ready,
		ctx:                ctx,
		cancel:             cancel,
	}
	server.connectedProxies.Store(proxyID, conn)
	require.NoError(t, controller.RegisterProxyToCluster(context.Background(), cluster, proxyID))
	t.Cleanup(func() {
		cancel()
		server.connectedProxies.Delete(proxyID)
		_ = controller.UnregisterProxyFromCluster(context.Background(), cluster, proxyID)
	})
	return conn, cancel
}

func callDiscoverModels(
	server *ProxyServiceServer,
	ctx context.Context,
	accountID, cluster string,
	req *proto.ModelDiscoveryRequest,
) <-chan modelDiscoveryCall {
	done := make(chan modelDiscoveryCall, 1)
	go func() {
		result, err := server.DiscoverModels(ctx, accountID, cluster, req)
		done <- modelDiscoveryCall{result: result, err: err}
	}()
	return done
}

func TestDiscoverModels_CorrelatesResultAndCopiesSensitiveRequest(t *testing.T) {
	server, controller := newModelDiscoveryTestServer(t)
	conn, _ := addModelDiscoveryTestConnection(
		t, server, controller, "proxy-a", "session-a", "cluster.example.com", nil, true,
	)

	callerReq := &proto.ModelDiscoveryRequest{
		RequestId:       "caller-controlled",
		UpstreamUrl:     "http://ollama.internal:11434",
		AuthHeaderName:  "Authorization",
		AuthHeaderValue: "Bearer secret",
		SkipTlsVerify:   true,
		OllamaFallback:  true,
	}
	done := callDiscoverModels(server, context.Background(), "account-a", "cluster.example.com", callerReq)

	wireReq := <-conn.modelDiscoveryChan
	assert.NotEmpty(t, wireReq.GetRequestId())
	assert.NotEqual(t, callerReq.GetRequestId(), wireReq.GetRequestId(), "management must own correlation IDs")
	assert.Equal(t, callerReq.GetUpstreamUrl(), wireReq.GetUpstreamUrl())
	assert.Equal(t, callerReq.GetAuthHeaderName(), wireReq.GetAuthHeaderName())
	assert.Equal(t, callerReq.GetAuthHeaderValue(), wireReq.GetAuthHeaderValue())
	assert.Equal(t, callerReq.GetSkipTlsVerify(), wireReq.GetSkipTlsVerify())
	assert.Equal(t, callerReq.GetOllamaFallback(), wireReq.GetOllamaFallback())
	assert.Equal(t, "caller-controlled", callerReq.GetRequestId(), "caller request must not be mutated")

	want := &proto.ModelDiscoveryResult{
		RequestId: wireReq.GetRequestId(),
		Models: []*proto.ModelDiscoveryModel{
			{Id: "llama3.2:latest", Label: "llama3.2:latest"},
		},
		Source: "openai_v1_models",
	}
	server.completeModelDiscovery(conn, want)

	got := <-done
	require.NoError(t, got.err)
	assert.Equal(t, want, got.result)
}

func TestDiscoverModels_IgnoresMismatchedCorrelation(t *testing.T) {
	server, controller := newModelDiscoveryTestServer(t)
	conn, _ := addModelDiscoveryTestConnection(
		t, server, controller, "proxy-a", "session-a", "cluster.example.com", nil, true,
	)

	done := callDiscoverModels(server, context.Background(), "account-a", "cluster.example.com", &proto.ModelDiscoveryRequest{
		UpstreamUrl: "http://ollama.internal:11434",
	})
	wireReq := <-conn.modelDiscoveryChan

	server.completeModelDiscovery(conn, &proto.ModelDiscoveryResult{RequestId: "wrong-request"})
	select {
	case got := <-done:
		t.Fatalf("mismatched request completed discovery: %+v", got)
	default:
	}

	wrongSession := *conn
	wrongSession.sessionID = "session-b"
	server.completeModelDiscovery(&wrongSession, &proto.ModelDiscoveryResult{RequestId: wireReq.GetRequestId()})
	select {
	case got := <-done:
		t.Fatalf("mismatched proxy session completed discovery: %+v", got)
	default:
	}

	server.completeModelDiscovery(conn, &proto.ModelDiscoveryResult{RequestId: wireReq.GetRequestId()})
	got := <-done
	require.NoError(t, got.err)
	require.NotNil(t, got.result)
}

func TestDiscoverModels_ReturnsProxyReportedErrorForManagerContext(t *testing.T) {
	server, controller := newModelDiscoveryTestServer(t)
	conn, _ := addModelDiscoveryTestConnection(
		t, server, controller, "proxy-a", "session-a", "cluster.example.com", nil, true,
	)

	done := callDiscoverModels(server, context.Background(), "account-a", "cluster.example.com", &proto.ModelDiscoveryRequest{
		UpstreamUrl: "http://ollama.internal:11434",
	})
	wireReq := <-conn.modelDiscoveryChan
	server.completeModelDiscovery(conn, &proto.ModelDiscoveryResult{
		RequestId: wireReq.GetRequestId(),
		Error:     "upstream returned HTTP 401",
	})

	got := <-done
	require.NoError(t, got.err)
	require.NotNil(t, got.result)
	assert.Equal(t, "upstream returned HTTP 401", got.result.GetError())
	assert.Equal(t, wireReq.GetRequestId(), got.result.GetRequestId())
}

func TestDiscoverModels_FiltersCapabilityAndAccountScope(t *testing.T) {
	tests := []struct {
		name              string
		connectionAccount *string
		requestAccount    string
		supported         bool
	}{
		{
			name:           "capability absent",
			requestAccount: "account-a",
			supported:      false,
		},
		{
			name:              "BYOP account mismatch",
			connectionAccount: stringPointer("account-b"),
			requestAccount:    "account-a",
			supported:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, controller := newModelDiscoveryTestServer(t)
			addModelDiscoveryTestConnection(
				t, server, controller, "proxy-a", "session-a", "cluster.example.com",
				tt.connectionAccount, tt.supported,
			)

			result, err := server.DiscoverModels(
				context.Background(),
				tt.requestAccount,
				"cluster.example.com",
				&proto.ModelDiscoveryRequest{UpstreamUrl: "http://ollama.internal:11434"},
			)
			require.Nil(t, result)
			requireStatusType(t, err, nbstatus.PreconditionFailed)
		})
	}
}

func TestDiscoverModels_RejectsStaleClusterMembershipAfterReconnect(t *testing.T) {
	server, controller := newModelDiscoveryTestServer(t)
	conn, _ := addModelDiscoveryTestConnection(
		t, server, controller, "proxy-a", "new-session", "new-cluster.example.com", nil, true,
	)
	// Simulate the stale membership left behind when this proxy ID previously
	// connected to another cluster and that superseded session skipped cleanup.
	require.NoError(t, controller.RegisterProxyToCluster(
		context.Background(),
		"old-cluster.example.com",
		"proxy-a",
	))

	result, err := server.DiscoverModels(
		context.Background(),
		"account-a",
		"old-cluster.example.com",
		&proto.ModelDiscoveryRequest{UpstreamUrl: "http://ollama.internal:11434"},
	)

	require.Nil(t, result)
	requireStatusType(t, err, nbstatus.PreconditionFailed)
	select {
	case request := <-conn.modelDiscoveryChan:
		t.Fatalf("sent credentials to connection in a different cluster: %+v", request)
	default:
	}
}

func TestDiscoverModels_CancelAndDisconnectCleanPendingRequest(t *testing.T) {
	t.Run("caller cancellation", func(t *testing.T) {
		server, controller := newModelDiscoveryTestServer(t)
		conn, _ := addModelDiscoveryTestConnection(
			t, server, controller, "proxy-a", "session-a", "cluster.example.com", nil, true,
		)
		ctx, cancel := context.WithCancel(context.Background())
		done := callDiscoverModels(server, ctx, "account-a", "cluster.example.com", &proto.ModelDiscoveryRequest{
			UpstreamUrl: "http://ollama.internal:11434",
		})
		<-conn.modelDiscoveryChan
		cancel()

		got := <-done
		require.Nil(t, got.result)
		requireStatusType(t, got.err, nbstatus.PreconditionFailed)
		assert.Empty(t, server.modelDiscoveryPending)
	})

	t.Run("proxy disconnect", func(t *testing.T) {
		server, controller := newModelDiscoveryTestServer(t)
		conn, _ := addModelDiscoveryTestConnection(
			t, server, controller, "proxy-a", "session-a", "cluster.example.com", nil, true,
		)
		done := callDiscoverModels(server, context.Background(), "account-a", "cluster.example.com", &proto.ModelDiscoveryRequest{
			UpstreamUrl: "http://ollama.internal:11434",
		})
		<-conn.modelDiscoveryChan
		server.failModelDiscoveries(conn, rpproxy.ErrModelDiscoveryUnavailable)

		got := <-done
		require.Nil(t, got.result)
		requireStatusType(t, got.err, nbstatus.PreconditionFailed)
		assert.Empty(t, server.modelDiscoveryPending)
	})
}

func TestDiscoverModels_UsesNextCapableProxyWhenFirstQueueIsFull(t *testing.T) {
	server, controller := newModelDiscoveryTestServer(t)
	first, _ := addModelDiscoveryTestConnection(
		t, server, controller, "proxy-a", "session-a", "cluster.example.com", nil, true,
	)
	second, _ := addModelDiscoveryTestConnection(
		t, server, controller, "proxy-b", "session-b", "cluster.example.com", nil, true,
	)
	first.modelDiscoveryChan = make(chan *proto.ModelDiscoveryRequest, 1)
	first.modelDiscoveryChan <- &proto.ModelDiscoveryRequest{RequestId: "occupied"}

	done := callDiscoverModels(server, context.Background(), "account-a", "cluster.example.com", &proto.ModelDiscoveryRequest{
		UpstreamUrl: "http://ollama.internal:11434",
	})
	wireReq := <-second.modelDiscoveryChan
	server.completeModelDiscovery(second, &proto.ModelDiscoveryResult{RequestId: wireReq.GetRequestId()})

	got := <-done
	require.NoError(t, got.err)
	require.NotNil(t, got.result)
}

func TestSenderSkipsCanceledQueuedModelDiscovery(t *testing.T) {
	server, controller := newModelDiscoveryTestServer(t)
	conn, _ := addModelDiscoveryTestConnection(
		t, server, controller, "proxy-a", "session-a", "cluster.example.com", nil, true,
	)
	stream := conn.syncStream.(*syncRecordingStream)

	ctx, cancel := context.WithCancel(context.Background())
	done := callDiscoverModels(server, ctx, "account-a", "cluster.example.com", &proto.ModelDiscoveryRequest{
		UpstreamUrl: "http://ollama.internal:11434",
	})
	require.Eventually(t, func() bool {
		return len(conn.modelDiscoveryChan) == 1
	}, time.Second, time.Millisecond)
	cancel()
	got := <-done
	require.Nil(t, got.result)
	requireStatusType(t, got.err, nbstatus.PreconditionFailed)

	liveRequest := &proto.ModelDiscoveryRequest{RequestId: "live-request"}
	livePending := &pendingModelDiscovery{
		proxyID:   conn.proxyID,
		sessionID: conn.sessionID,
		done:      make(chan modelDiscoveryCompletion, 1),
	}
	server.registerModelDiscovery(liveRequest.GetRequestId(), livePending)
	defer server.removeModelDiscovery(liveRequest.GetRequestId(), livePending)
	conn.modelDiscoveryChan <- liveRequest

	errCh := make(chan error, 1)
	go server.sender(conn, errCh)
	require.Eventually(t, func() bool {
		stream.mu.Lock()
		defer stream.mu.Unlock()
		return len(stream.sent) == 1
	}, time.Second, time.Millisecond)

	stream.mu.Lock()
	sent := append([]*proto.SyncMappingsResponse(nil), stream.sent...)
	stream.mu.Unlock()
	require.Len(t, sent, 1)
	assert.Equal(t, "live-request", sent[0].GetModelDiscoveryRequest().GetRequestId())
}

func TestDrainRecv_DispatchesModelDiscoveryResult(t *testing.T) {
	server, _ := newModelDiscoveryTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := &proxyConnection{
		proxyID:   "proxy-a",
		sessionID: "session-a",
		ctx:       ctx,
		cancel:    cancel,
	}
	pending := &pendingModelDiscovery{
		proxyID:   conn.proxyID,
		sessionID: conn.sessionID,
		done:      make(chan modelDiscoveryCompletion, 1),
	}
	server.registerModelDiscovery("request-a", pending)
	stream := &syncRecordingStream{
		recvMsgs: []*proto.SyncMappingsRequest{
			{
				Msg: &proto.SyncMappingsRequest_ModelDiscoveryResult{
					ModelDiscoveryResult: &proto.ModelDiscoveryResult{RequestId: "request-a"},
				},
			},
		},
	}
	errCh := make(chan error, 1)

	go server.drainRecv(conn, stream, errCh)

	completion := <-pending.done
	require.NoError(t, completion.err)
	require.NotNil(t, completion.result)
	assert.Equal(t, "request-a", completion.result.GetRequestId())
}

func TestSendModelDiscoveryRequest_UsesOutOfBandSyncField(t *testing.T) {
	stream := &syncRecordingStream{}
	conn := &proxyConnection{syncStream: stream}
	req := &proto.ModelDiscoveryRequest{RequestId: "request-a"}

	require.NoError(t, conn.sendModelDiscoveryRequest(req))
	require.Len(t, stream.sent, 1)
	assert.Empty(t, stream.sent[0].GetMapping())
	assert.Equal(t, req, stream.sent[0].GetModelDiscoveryRequest())
}

func stringPointer(value string) *string {
	return &value
}

func requireStatusType(t *testing.T, err error, want nbstatus.Type) {
	t.Helper()
	require.Error(t, err)
	statusErr, ok := nbstatus.FromError(err)
	require.True(t, ok)
	assert.Equal(t, want, statusErr.Type())
}
