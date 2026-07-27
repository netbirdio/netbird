package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/proxy/internal/crowdsec"
	"github.com/netbirdio/netbird/proxy/internal/modeldiscovery"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type stubModelDiscoverer struct {
	started chan modeldiscovery.Request
	release <-chan struct{}
	result  modeldiscovery.Result
	err     error
}

func (s *stubModelDiscoverer) Discover(ctx context.Context, request modeldiscovery.Request) (modeldiscovery.Result, error) {
	if s.started != nil {
		select {
		case s.started <- request:
		case <-ctx.Done():
			return modeldiscovery.Result{}, ctx.Err()
		}
	}
	if s.release != nil {
		select {
		case <-s.release:
		case <-ctx.Done():
			return modeldiscovery.Result{}, ctx.Err()
		}
	}
	return s.result, s.err
}

type modelDiscoverySyncStream struct {
	grpc.ClientStream
	ctx      context.Context
	recv     chan *proto.SyncMappingsResponse
	sent     chan *proto.SyncMappingsRequest
	sendWait time.Duration
	sending  atomic.Int32
	overlap  atomic.Bool
}

func newModelDiscoverySyncStream(ctx context.Context) *modelDiscoverySyncStream {
	return &modelDiscoverySyncStream{
		ctx:  ctx,
		recv: make(chan *proto.SyncMappingsResponse, 16),
		sent: make(chan *proto.SyncMappingsRequest, 16),
	}
}

func (s *modelDiscoverySyncStream) Send(message *proto.SyncMappingsRequest) error {
	if s.sending.Add(1) != 1 {
		s.overlap.Store(true)
	}
	defer s.sending.Add(-1)
	if s.sendWait > 0 {
		time.Sleep(s.sendWait)
	}
	select {
	case s.sent <- message:
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

func (s *modelDiscoverySyncStream) Recv() (*proto.SyncMappingsResponse, error) {
	select {
	case message, ok := <-s.recv:
		if !ok {
			return nil, io.EOF
		}
		return message, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

func (s *modelDiscoverySyncStream) Context() context.Context {
	return s.ctx
}

func completeModelDiscoveryInitialSync(t *testing.T, stream *modelDiscoverySyncStream) {
	t.Helper()
	stream.recv <- &proto.SyncMappingsResponse{InitialSyncComplete: true}
	select {
	case sent := <-stream.sent:
		require.NotNil(t, sent.GetAck())
	case <-time.After(time.Second):
		t.Fatal("initial snapshot was not acknowledged")
	}
}

func TestProxyCapabilitiesAdvertiseModelDiscovery(t *testing.T) {
	t.Parallel()

	server := &Server{
		crowdsecRegistry: crowdsec.NewRegistry("", "", log.New().WithField("test", true)),
	}
	capabilities := server.proxyCapabilities()
	require.NotNil(t, capabilities.SupportsModelDiscovery)
	assert.True(t, capabilities.GetSupportsModelDiscovery())
}

func TestExecuteModelDiscoveryMapsControlShape(t *testing.T) {
	t.Parallel()

	discoverer := &stubModelDiscoverer{
		result: modeldiscovery.Result{
			Source: modeldiscovery.SourceOpenAIV1Models,
			Models: []modeldiscovery.Model{
				{ID: "llama3.2:latest", Label: "Llama 3.2"},
			},
		},
	}
	request := &proto.ModelDiscoveryRequest{
		RequestId:       "request-1",
		UpstreamUrl:     "http://ollama.internal:11434",
		AuthHeaderName:  "Authorization",
		AuthHeaderValue: "Bearer secret",
		SkipTlsVerify:   true,
		OllamaFallback:  true,
	}

	result := executeModelDiscovery(context.Background(), discoverer, request)
	assert.Equal(t, "request-1", result.GetRequestId())
	assert.Equal(t, modeldiscovery.SourceOpenAIV1Models, result.GetSource())
	require.Len(t, result.GetModels(), 1)
	assert.Equal(t, "llama3.2:latest", result.GetModels()[0].GetId())
	assert.Equal(t, "Llama 3.2", result.GetModels()[0].GetLabel())

	discoverer.started = make(chan modeldiscovery.Request, 1)
	_ = executeModelDiscovery(context.Background(), discoverer, request)
	received := <-discoverer.started
	assert.Equal(t, request.GetUpstreamUrl(), received.UpstreamURL)
	assert.Equal(t, request.GetAuthHeaderName(), received.AuthHeaderName)
	assert.Equal(t, request.GetAuthHeaderValue(), received.AuthHeaderValue)
	assert.True(t, received.SkipTLSVerify)
	assert.True(t, received.AllowOllamaFallback)
}

func TestExecuteModelDiscoveryReturnsSanitizedError(t *testing.T) {
	t.Parallel()

	result := executeModelDiscovery(context.Background(), &stubModelDiscoverer{
		err: errors.New("model discovery request failed"),
	}, &proto.ModelDiscoveryRequest{RequestId: "request-error"})
	assert.Equal(t, "request-error", result.GetRequestId())
	assert.Equal(t, "model discovery request failed", result.GetError())
	assert.Empty(t, result.GetModels())
	assert.Empty(t, result.GetSource())
}

func TestHandleSyncMappingsStreamRunsDiscoveryOutOfBand(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	release := make(chan struct{})
	started := make(chan modeldiscovery.Request, 1)
	server := &Server{
		Logger:      log.New(),
		routerReady: closedChan(),
		modelDiscoverer: &stubModelDiscoverer{
			started: started,
			release: release,
			result: modeldiscovery.Result{
				Source: modeldiscovery.SourceOpenAIV1Models,
				Models: []modeldiscovery.Model{{ID: "model-a", Label: "model-a"}},
			},
		},
	}
	stream := newModelDiscoverySyncStream(ctx)
	stream.sendWait = 10 * time.Millisecond

	done := make(chan error, 1)
	initialSyncDone := false
	go func() {
		done <- server.handleSyncMappingsStream(ctx, stream, &initialSyncDone, time.Time{})
	}()
	completeModelDiscoveryInitialSync(t, stream)

	stream.recv <- &proto.SyncMappingsResponse{
		ModelDiscoveryRequest: &proto.ModelDiscoveryRequest{
			RequestId:   "request-1",
			UpstreamUrl: "http://ollama.internal:11434",
		},
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("model discovery did not start")
	}

	// A normal mapping batch must still be acknowledged while the HTTP probe
	// is in flight.
	stream.recv <- &proto.SyncMappingsResponse{}
	select {
	case sent := <-stream.sent:
		assert.NotNil(t, sent.GetAck())
		assert.Nil(t, sent.GetModelDiscoveryResult())
	case <-time.After(time.Second):
		t.Fatal("mapping ack was blocked by model discovery")
	}

	close(release)
	select {
	case sent := <-stream.sent:
		result := sent.GetModelDiscoveryResult()
		require.NotNil(t, result)
		assert.Equal(t, "request-1", result.GetRequestId())
		assert.Equal(t, modeldiscovery.SourceOpenAIV1Models, result.GetSource())
		assert.Nil(t, sent.GetAck())
	case <-time.After(time.Second):
		t.Fatal("model discovery result was not sent")
	}
	assert.False(t, stream.overlap.Load(), "acks and discovery results must use one serialized sender")

	close(stream.recv)
	require.NoError(t, <-done)
}

func TestHandleSyncMappingsStreamBoundsConcurrentDiscovery(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	release := make(chan struct{})
	started := make(chan modeldiscovery.Request, 8)
	server := &Server{
		Logger:      log.New(),
		routerReady: closedChan(),
		modelDiscoverer: &stubModelDiscoverer{
			started: started,
			release: release,
		},
	}
	stream := newModelDiscoverySyncStream(ctx)

	done := make(chan error, 1)
	initialSyncDone := false
	go func() {
		done <- server.handleSyncMappingsStream(ctx, stream, &initialSyncDone, time.Time{})
	}()
	completeModelDiscoveryInitialSync(t, stream)

	for i := range 5 {
		stream.recv <- &proto.SyncMappingsResponse{
			ModelDiscoveryRequest: &proto.ModelDiscoveryRequest{
				RequestId:   fmt.Sprintf("request-%d", i),
				UpstreamUrl: "http://ollama.internal:11434",
			},
		}
	}

	for range 4 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("expected four concurrent model discoveries")
		}
	}
	select {
	case sent := <-stream.sent:
		result := sent.GetModelDiscoveryResult()
		require.NotNil(t, result)
		assert.Equal(t, "model discovery is busy", result.GetError())
	case <-time.After(time.Second):
		t.Fatal("fifth discovery did not fail fast")
	}

	close(release)
	for range 4 {
		select {
		case sent := <-stream.sent:
			require.NotNil(t, sent.GetModelDiscoveryResult())
		case <-time.After(time.Second):
			t.Fatal("in-flight model discovery did not complete")
		}
	}
	close(stream.recv)
	require.NoError(t, <-done)
}

func TestHandleSyncMappingsStreamRejectsMixedDiscoveryMessage(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := &Server{
		Logger:          log.New(),
		routerReady:     closedChan(),
		modelDiscoverer: &stubModelDiscoverer{},
	}
	stream := newModelDiscoverySyncStream(ctx)
	stream.recv <- &proto.SyncMappingsResponse{
		Mapping:             []*proto.ProxyMapping{{Id: "mapping-1"}},
		InitialSyncComplete: true,
		ModelDiscoveryRequest: &proto.ModelDiscoveryRequest{
			RequestId: "request-1",
		},
	}
	close(stream.recv)

	initialSyncDone := true
	err := server.handleSyncMappingsStream(ctx, stream, &initialSyncDone, time.Time{})
	require.EqualError(t, err, "model discovery message must not include mapping data or set initial_sync_complete")
}

func TestHandleSyncMappingsStreamRejectsDiscoveryBeforeInitialSnapshot(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := &Server{
		Logger:          log.New(),
		routerReady:     closedChan(),
		modelDiscoverer: &stubModelDiscoverer{},
	}
	stream := newModelDiscoverySyncStream(ctx)
	stream.recv <- &proto.SyncMappingsResponse{
		ModelDiscoveryRequest: &proto.ModelDiscoveryRequest{
			RequestId: "request-1",
		},
	}
	close(stream.recv)

	initialSyncDone := true
	err := server.handleSyncMappingsStream(ctx, stream, &initialSyncDone, time.Time{})
	require.EqualError(t, err, "model discovery request received before initial sync completed")
}
