package server

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"google.golang.org/grpc/metadata"

	"github.com/netbirdio/netbird/shared/signal/proto"
	"github.com/netbirdio/netbird/signal/metrics/metricstest"
	"github.com/netbirdio/netbird/signal/peer"
)

// brokenStream fails every Send, as a peer stream whose transport broke does.
type brokenStream struct {
	proto.SignalExchange_ConnectStreamServer
}

func (s *brokenStream) Send(*proto.EncryptedMessage) error { return errors.New("stream broken") }

func (s *brokenStream) Context() context.Context { return context.Background() }

// TestSendMetrics verifies that every message received through Send is counted
// once at ingress, with its size and probe status, and once by its outcome.
func TestSendMetrics(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	s, err := NewServer(context.Background(), provider.Meter("test"))
	require.NoError(t, err)

	const (
		localPeer  = "local-peer"
		brokenPeer = "broken-peer"
		remotePeer = "remote-peer"
	)
	require.NoError(t, s.registry.Register(peer.NewPeer(localPeer, &concurrencyCheckStream{ctx: context.Background()}, func() {})))
	require.NoError(t, s.registry.Register(peer.NewPeer(brokenPeer, &brokenStream{}, func() {})))

	ctx := context.Background()
	for _, msg := range []*proto.EncryptedMessage{
		{Key: localPeer, RemoteKey: localPeer},
		{Key: localPeer, RemoteKey: localPeer},
		{Key: remotePeer, RemoteKey: localPeer},
		{Key: localPeer, RemoteKey: brokenPeer},
		{Key: remotePeer, RemoteKey: remotePeer},
		{Key: localPeer, RemoteKey: remotePeer},
	} {
		_, err := s.Send(ctx, msg)
		require.NoError(t, err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = s.Send(cancelled, &proto.EncryptedMessage{Key: localPeer, RemoteKey: remotePeer})
	require.Error(t, err, "a dispatcher failure must reach the caller")

	rm := metricstest.Collect(t, reader)
	assert.Equal(t, map[string]int64{labelRouteLocal: 4, labelRouteRemote: 3}, metricstest.SumByAttribute(t, rm, "messages_received_total", labelRoute))
	assert.Equal(t, map[string]uint64{labelRouteLocal: 4, labelRouteRemote: 3}, metricstest.HistogramCountByAttribute(t, rm, "message.size.bytes", labelRoute), "every received message must record its size")
	assert.Equal(t, map[string]uint64{labelResultDelivered: 3, labelTypeError: 1}, metricstest.HistogramCountByAttribute(t, rm, "message_forward_latency_milliseconds", labelResult), "every delivery attempt must record its latency")
	assert.Equal(t, map[string]int64{labelRouteLocal: 2, labelRouteRemote: 1}, metricstest.SumByAttribute(t, rm, "probe_messages_total", labelRoute))
	assert.Equal(t, map[string]int64{labelRouteLocal: 3, labelRouteRemote: 2}, metricstest.SumByAttribute(t, rm, "send_success_total", labelRoute))
	assert.Equal(t, map[string]int64{labelTypeError: 1, labelTypeDispatch: 1}, metricstest.SumByAttribute(t, rm, "send_failures_total", labelType))
	assert.Equal(t, map[string]int64{labelRouteLocal: 1, labelRouteRemote: 1}, metricstest.SumByAttribute(t, rm, "send_failures_total", labelRoute))
	assert.Equal(t, map[string]int64{"": 0}, metricstest.SumByAttribute(t, rm, "send_inflight", labelRoute), "no Send may remain in flight")
	assert.Equal(t, map[string]int64{"": 3}, metricstest.SumByAttribute(t, rm, "messages_forwarded_total", labelType))
	assert.Equal(t, map[string]int64{labelTypeError: 1}, metricstest.SumByAttribute(t, rm, "message_forward_failures_total", labelType))
}

// TestRegisterPeerMetrics verifies that a successful registration records its
// duration and that a stream losing to a newer registration counts as a failure
// without changing the active peers.
func TestRegisterPeerMetrics(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	s, err := NewServer(context.Background(), provider.Meter("test"))
	require.NoError(t, err)

	streamFor := func(id string) *concurrencyCheckStream {
		return &concurrencyCheckStream{ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs(proto.HeaderId, id))}
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	_, err = s.RegisterPeer(streamFor("peer"), cancel)
	require.NoError(t, err)

	newer := peer.NewPeer("newer", streamFor("newer"), func() {})
	newer.StreamID = math.MaxInt64
	require.NoError(t, s.registry.Register(newer))
	_, err = s.RegisterPeer(streamFor("newer"), func() {})
	require.ErrorIs(t, err, peer.ErrPeerAlreadyRegistered)

	rm := metricstest.Collect(t, reader)
	assert.Equal(t, map[string]uint64{"": 1}, metricstest.HistogramCountByAttribute(t, rm, "registration_delay_milliseconds", labelError), "only the successful registration records a duration")
	assert.Equal(t, map[string]int64{labelErrorAlreadyRegistered: 1}, metricstest.SumByAttribute(t, rm, "registration_failures_total", labelError))
	assert.Equal(t, map[string]int64{"": 2}, metricstest.SumByAttribute(t, rm, "active_peers", labelError))
	require.NoError(t, ctx.Err())
}
