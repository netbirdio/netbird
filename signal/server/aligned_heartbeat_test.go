package server

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/grpc/metadata"

	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/relay/messages"
	"github.com/netbirdio/netbird/shared/signal/proto"
	"github.com/netbirdio/netbird/signal/metrics/metricstest"
	"github.com/netbirdio/netbird/signal/peer"
)

// hbStream is a ConnectStream stream that records what the server sends and
// when.
type hbStream struct {
	proto.SignalExchange_ConnectStreamServer
	ctx    context.Context
	mu     sync.Mutex
	msgs   []*proto.EncryptedMessage
	times  []time.Time
	header metadata.MD
}

func (s *hbStream) Context() context.Context { return s.ctx }

func (s *hbStream) Send(m *proto.EncryptedMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.msgs = append(s.msgs, m)
	s.times = append(s.times, time.Now())
	return nil
}

func (s *hbStream) SendHeader(md metadata.MD) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.header = md.Copy()
	return nil
}

func (s *hbStream) SetHeader(metadata.MD) error { return nil }

func (s *hbStream) sent() ([]*proto.EncryptedMessage, []time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*proto.EncryptedMessage(nil), s.msgs...), append([]time.Time(nil), s.times...)
}

// connectPeer runs ConnectStream for a stream with metadata md until the
// returned stop is called, and returns the stream and the ConnectStream
// result channel.
func connectPeer(t *testing.T, s *Server, md metadata.MD) (*hbStream, <-chan error, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(metadata.NewIncomingContext(context.Background(), md))
	t.Cleanup(cancel)
	stream := &hbStream{ctx: ctx}
	done := make(chan error, 1)
	go func() { done <- s.ConnectStream(stream) }()
	require.Eventually(t, func() bool {
		stream.mu.Lock()
		defer stream.mu.Unlock()
		return stream.header != nil
	}, time.Second, 10*time.Millisecond, "the peer gets its registration header")
	return stream, done, cancel
}

func TestAlignedHeartbeatAnswer(t *testing.T) {
	s, err := NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	const peerKey = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMjA="
	ctxWith := func(v string) context.Context {
		return metadata.NewIncomingContext(context.Background(), metadata.Pairs(alignedhb.MetadataKey, v))
	}

	assert.Nil(t, s.alignedHeartbeatAnswer(context.Background(), peerKey), "no metadata must stay stock")
	assert.Nil(t, s.alignedHeartbeatAnswer(ctxWith("garbage"), peerKey), "a bad value must stay stock")
	assert.Nil(t, s.alignedHeartbeatAnswer(ctxWith("period=60x"), peerKey), "a bad value must stay stock")

	for value, want := range map[string]time.Duration{"period=60": time.Minute, "period=60;phase=1": time.Minute, "period=1": 30 * time.Second, "period=1000": 300 * time.Second} {
		got := s.alignedHeartbeatAnswer(ctxWith(value), peerKey)
		require.NotNil(t, got, value)
		assert.Equal(t, want, got.period, "%s: clamped period", value)
		assert.Equal(t, alignedhb.Phase(messages.HashID(peerKey), want), got.phase,
			"%s: Signal must tick on the phase Management and relay compute for the same peer", value)
	}
}

// Heartbeats go out on the phase with an empty sender key and an empty
// body. A stream without an answer never gets one.
func TestStartAlignedHeartbeat(t *testing.T) {
	s, err := NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	const peerKey = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMjM="
	answer := &alignedAnswer{period: 30 * time.Second, phase: 12345 * time.Millisecond}

	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		aligned := &hbStream{ctx: ctx}
		stock := &hbStream{ctx: ctx}
		stopAligned := s.startAlignedHeartbeat(ctx, peer.NewPeer(peerKey, aligned, cancel), answer)
		defer stopAligned()
		stopStock := s.startAlignedHeartbeat(ctx, peer.NewPeer(peerKey, stock, cancel), nil)
		defer stopStock()

		time.Sleep(3 * answer.period)
		synctest.Wait()

		msgs, times := aligned.sent()
		require.Len(t, msgs, 3, "one heartbeat per period")
		for i, m := range msgs {
			assert.NotNil(t, m.GetServerHeartbeat(), "heartbeat %d carries the server heartbeat", i)
			assert.Empty(t, m.GetKey(), "heartbeat %d has no sender key", i)
			assert.Empty(t, m.GetBody(), "heartbeat %d has no body", i)
			assert.Equal(t, peerKey, m.GetRemoteKey())
			assert.Equal(t, answer.phase.Milliseconds(), times[i].UnixMilli()%answer.period.Milliseconds(),
				"heartbeat %d on the phase", i)
		}
		stockMsgs, _ := stock.sent()
		assert.Empty(t, stockMsgs, "a stream without an answer gets no heartbeat")
	})
}

// A peer-forged server heartbeat never reaches the victim, neither on the
// local path nor through the dispatcher, and the sender's message is not
// changed.
func TestSendStripsServerHeartbeat(t *testing.T) {
	s, err := NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const localVictim = "local-victim"
	localStream := &hbStream{ctx: ctx}
	require.NoError(t, s.registry.Register(peer.NewPeer(localVictim, localStream, cancel)))

	// A victim on another instance is reached only through the dispatcher.
	const remoteVictim = "remote-victim"
	remote := make(chan *proto.EncryptedMessage, 1)
	require.NoError(t, s.dispatcher.ListenForMessages(ctx, remoteVictim, func(_ context.Context, m *proto.EncryptedMessage) {
		remote <- m
	}))

	forged := func(victim string) *proto.EncryptedMessage {
		return &proto.EncryptedMessage{Key: "sender-peer", RemoteKey: victim, Body: []byte("payload"), ServerHeartbeat: &proto.ServerHeartbeat{}}
	}

	toLocal := forged(localVictim)
	_, err = s.Send(context.Background(), toLocal)
	require.NoError(t, err)
	msgs, _ := localStream.sent()
	require.Len(t, msgs, 1, "the local victim gets the message")
	assert.Nil(t, msgs[0].GetServerHeartbeat(), "local path: field 5 must be stripped before delivery")
	assert.Equal(t, []byte("payload"), msgs[0].GetBody(), "local path: the rest of the message is forwarded")
	assert.NotNil(t, toLocal.GetServerHeartbeat(), "the sender's message must not be changed")

	toRemote := forged(remoteVictim)
	_, err = s.Send(context.Background(), toRemote)
	require.NoError(t, err)
	select {
	case m := <-remote:
		assert.Nil(t, m.GetServerHeartbeat(), "dispatcher path: field 5 must be stripped before dispatch")
		assert.Equal(t, []byte("payload"), m.GetBody(), "dispatcher path: the rest of the message is forwarded")
	case <-time.After(2 * time.Second):
		t.Fatal("the dispatcher did not deliver within 2s")
	}
	assert.NotNil(t, toRemote.GetServerHeartbeat(), "the sender's message must not be changed")
}

// The aligned gauge counts aligned streams while they run. A stream
// replaced by a new registration of the same peer stops its heartbeat and
// its count.
func TestAlignedGauge(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	s, err := NewServer(context.Background(), provider.Meter("test"))
	require.NoError(t, err)
	const peerKey = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMjQ="

	gauge := func() int64 {
		rm := metricstest.Collect(t, reader)
		var total int64
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				if m.Name != "aligned_streams" {
					continue
				}
				sum, ok := m.Data.(metricdata.Sum[int64])
				if !ok {
					continue
				}
				for _, dp := range sum.DataPoints {
					total += dp.Value
				}
			}
		}
		return total
	}

	_, stockDone, stopStock := connectPeer(t, s, metadata.Pairs(proto.HeaderId, "stock-peer"))
	assert.Equal(t, int64(0), gauge(), "a stock stream is not counted")
	stopStock()
	require.NoError(t, <-stockDone)

	md := metadata.Pairs(proto.HeaderId, peerKey, alignedhb.MetadataKey, "period=60")
	_, firstDone, _ := connectPeer(t, s, md)
	assert.Eventually(t, func() bool { return gauge() == 1 }, 2*time.Second, 10*time.Millisecond, "aligned stream counted")

	_, secondDone, stopSecond := connectPeer(t, s, md)
	select {
	case err := <-firstDone:
		assert.True(t, errors.Is(err, ErrPeerRegisteredAgain), "the replaced stream ends with %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("the replaced stream did not end within 2s")
	}
	assert.Eventually(t, func() bool { return gauge() == 1 }, 2*time.Second, 10*time.Millisecond, "only the new stream is counted")

	stopSecond()
	require.NoError(t, <-secondDone)
	assert.Equal(t, int64(0), gauge(), "ended aligned stream uncounted")
}
