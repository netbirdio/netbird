package client

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/metadata"

	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/phasesig"
	"github.com/netbirdio/netbird/shared/relay/messages"
	sigProto "github.com/netbirdio/netbird/shared/signal/proto"
)

func peerOf(key wgtypes.Key) messages.PeerID {
	return messages.HashID(key.PublicKey().String())
}

// recordingSender records the frames written on a stream.
type recordingSender struct {
	mu   sync.Mutex
	msgs []*sigProto.EncryptedMessage
}

func (s *recordingSender) Send(m *sigProto.EncryptedMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.msgs = append(s.msgs, m)
	return nil
}

func (s *recordingSender) sent() []*sigProto.EncryptedMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*sigProto.EncryptedMessage(nil), s.msgs...)
}

// alignedPhase returns the phase of the aligned heartbeat on the stream, -1
// while it is stock.
func alignedPhase(c *GrpcClient) time.Duration {
	a, ok := c.alignedHeartbeat()
	if !ok {
		return -1
	}
	return a.Phase
}

// keyWithTickWithin returns a key whose signed phase for period next ticks
// at least lo and at most hi from now. The server ticks on the real floor, so
// a test that waits for a heartbeat picks such a key instead of waiting out a
// whole period; the wait below still covers a tick that slips past the window.
func keyWithTickWithin(t *testing.T, period, lo, hi time.Duration) wgtypes.Key {
	t.Helper()
	signer, err := phasesig.NewSigner(testPhaseSecret)
	require.NoError(t, err)
	for i := 0; i < 1000; i++ {
		key, err := wgtypes.GenerateKey()
		require.NoError(t, err)
		sp, err := signer.SignedPhase(messages.HashID(key.PublicKey().String()), period, time.Now())
		require.NoError(t, err)
		if d := alignedhb.NextDelay(period, sp.Phase, time.Now()); d >= lo && d <= hi {
			return key
		}
	}
	t.Fatalf("no key ticks within %s to %s of now", lo, hi)
	return wgtypes.Key{}
}

// A stream that opened before the Management answer gets the signed phase as
// soon as Management hands it out, and turns aligned on the same stream.
func TestSignalStreamAlignsAfterSignedPhase(t *testing.T) {
	const period = 30 * time.Second
	setAlignedRequest(t, period, true)
	srv := newRecordingSignalServer(t, false)
	key := keyWithTickWithin(t, period, 2*time.Second, 5*time.Second)
	client := connectAlignedTestClientWithKey(t, srv, key)
	var reconnects atomic.Int32
	client.SetOnReconnectedListener(func() { reconnects.Add(1) })

	require.NotNil(t, client.phase.Load(), "the server answered with the period, so the client may write")
	time.Sleep(1200 * time.Millisecond)
	require.Equal(t, time.Duration(-1), alignedPhase(client), "stock until the signed phase arrives")

	sp := storeTestSignedPhase(t, key, period)
	require.Eventually(t, func() bool { return alignedPhase(client) == sp.Phase }, 35*time.Second, 20*time.Millisecond,
		"Signal heartbeats must come on the signed phase")
	assert.Zero(t, reconnects.Load(), "no reconnect")
	srv.mu.Lock()
	assert.Len(t, srv.incoming, 1, "one stream")
	srv.mu.Unlock()
}

// A correction from the watcher moves the Signal heartbeats of an aligned
// stream to the requested phase.
func TestSignalStreamFollowsCorrection(t *testing.T) {
	const period = 30 * time.Second
	setAlignedRequest(t, period, true)
	srv := newRecordingSignalServer(t, false)
	key := keyWithTickWithin(t, period, time.Second, 3*time.Second)
	sp := storeTestSignedPhase(t, key, period)
	client := connectAlignedTestClientWithKey(t, srv, key)
	require.Eventually(t, func() bool { return alignedPhase(client) == sp.Phase }, 35*time.Second, 20*time.Millisecond)

	// The header answer already reports the phase, so wait for the first
	// heartbeat itself: the server takes a correction only after it ticked.
	// The corrected tick is one period after the heartbeat that allowed it.
	time.Sleep(alignedhb.NextDelay(period, sp.Phase, time.Now()) + 300*time.Millisecond)
	wanted := (sp.Phase + 450*time.Millisecond) % period
	client.phase.Load().correct(wanted)
	require.Eventually(t, func() bool { return alignedPhase(client) == wanted }, 45*time.Second, 20*time.Millisecond,
		"Signal heartbeats must move to the corrected phase")
	srv.mu.Lock()
	assert.Len(t, srv.incoming, 1, "one stream")
	srv.mu.Unlock()
}

// A server that sends no answer may not read the stream: the client never
// writes phase requests on it.
func TestSignalStreamNoPhaseWriterOnOldServer(t *testing.T) {
	setAlignedRequest(t, 30*time.Second, true)
	srv := newRecordingSignalServer(t, true)
	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	client := connectAlignedTestClientWithKey(t, srv, key)
	assert.Nil(t, client.phase.Load(), "no answer, no writes")

	storeTestSignedPhase(t, key, 30*time.Second)
	time.Sleep(1200 * time.Millisecond)
	_, ok := client.alignedHeartbeat()
	assert.False(t, ok, "the stream stays stock")
}

// A stream that sent the stored phase at open does not send it again, and a
// phase stored for another peer is never sent.
func TestPhaseWriterSendsOnlyNewPhases(t *testing.T) {
	setAlignedRequest(t, time.Minute, true)
	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	other, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	sp := storeTestSignedPhase(t, key, time.Minute)
	_, seq, ok := alignedStreamRequest(key.PublicKey().String())
	require.True(t, ok)
	require.NotZero(t, seq, "the stream open carries the stored phase")

	stream := &recordingSender{}
	var sendMu sync.Mutex
	w := newPhaseWriter(stream, &sendMu, peerOf(key), key.PublicKey().String(), time.Minute, seq)
	w.sendSignedPhase()
	storeTestSignedPhase(t, other, time.Minute)
	w.sendSignedPhase()
	time.Sleep(100 * time.Millisecond)
	assert.Empty(t, stream.sent(), "nothing new for this peer")

	next := sp
	next.Day++
	alignedhb.StoreSignedPhase(peerOf(key), time.Minute, next)
	w.sendSignedPhase()
	w.sendSignedPhase()
	require.Eventually(t, func() bool { return len(stream.sent()) == 1 }, time.Second, 10*time.Millisecond)
	req := stream.sent()[0].GetPhaseRequest()
	require.NotNil(t, req, "a phase request")
	assert.Equal(t, next.Day, req.GetPhaseDay(), "the new day")
	assert.Equal(t, uint32(60), req.GetPeriodSeconds(), "the signed period")
	assert.Equal(t, uint32(next.Phase.Milliseconds()), req.GetPhaseMillis(), "the signed phase")
	assert.Equal(t, next.Signature, req.GetPhaseSignature(), "the signature")
}

// forgingSignalServer stands for a Signal server that forwards whatever a peer
// sends, as servers from before the aligned heartbeat do. It answers the stream
// with answer, none when empty, and writes every message from msgs on it.
type forgingSignalServer struct {
	sigProto.UnimplementedSignalExchangeServer
	answer string
	msgs   chan *sigProto.EncryptedMessage
}

func (s *forgingSignalServer) ConnectStream(stream sigProto.SignalExchange_ConnectStreamServer) error {
	md := metadata.Pairs(sigProto.HeaderRegistered, "1")
	if s.answer != "" {
		md.Set(alignedhb.MetadataKey, s.answer)
	}
	if err := stream.SendHeader(md); err != nil {
		return err
	}
	for {
		select {
		case m := <-s.msgs:
			if err := stream.Send(m); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return nil
		}
	}
}

func connectForgingClient(t *testing.T, srv *forgingSignalServer) *GrpcClient {
	t.Helper()
	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	addr := serveTestSignalExchange(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	client, err := NewClient(ctx, addr, key, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	receiveDone := make(chan struct{})
	go func() {
		defer close(receiveDone)
		_ = client.Receive(ctx, func(*sigProto.Message) error { return nil })
	}()
	t.Cleanup(func() {
		cancel()
		<-receiveDone
	})
	require.Eventually(t, client.IsHealthy, 5*time.Second, 10*time.Millisecond, "stream must connect")
	return client
}

// A heartbeat that another peer put in a forwarded message carries its key, and
// must not count as a Signal heartbeat. A server heartbeat has no key.
func TestForwardedHeartbeatWithKeyIgnored(t *testing.T) {
	setAlignedRequest(t, time.Minute, true)
	srv := &forgingSignalServer{answer: alignedhb.PendingAnswerValue(time.Minute), msgs: make(chan *sigProto.EncryptedMessage, 4)}
	client := connectForgingClient(t, srv)
	require.NotNil(t, client.phase.Load(), "the server answered, so the stream may turn aligned")

	srv.msgs <- &sigProto.EncryptedMessage{Key: "attacker", ServerHeartbeat: &sigProto.ServerHeartbeat{PhaseMillis: 1234}}
	time.Sleep(300 * time.Millisecond)
	_, ok := client.alignedHeartbeat()
	assert.False(t, ok, "a heartbeat with a sender key must be ignored")

	srv.msgs <- &sigProto.EncryptedMessage{ServerHeartbeat: &sigProto.ServerHeartbeat{PhaseMillis: 1234}}
	require.Eventually(t, func() bool { return alignedPhase(client) == 1234*time.Millisecond }, 2*time.Second, 10*time.Millisecond,
		"a heartbeat from the server must count")
}

// A stream without the aligned answer gets no server heartbeats, so any it sees
// is forged and must not turn the aligned heartbeat on.
func TestHeartbeatWithoutAnswerIgnored(t *testing.T) {
	setAlignedRequest(t, time.Minute, true)
	srv := &forgingSignalServer{msgs: make(chan *sigProto.EncryptedMessage, 4)}
	client := connectForgingClient(t, srv)
	require.Nil(t, client.phase.Load(), "no answer, no aligned heartbeat")

	srv.msgs <- &sigProto.EncryptedMessage{ServerHeartbeat: &sigProto.ServerHeartbeat{PhaseMillis: 1234}}
	time.Sleep(300 * time.Millisecond)
	_, ok := client.alignedHeartbeat()
	assert.False(t, ok, "a heartbeat on a stream without the answer must be ignored")
	assert.Nil(t, client.serverHeartbeat(&sigProto.EncryptedMessage{ServerHeartbeat: &sigProto.ServerHeartbeat{}}),
		"no server heartbeat without the answer")
}
