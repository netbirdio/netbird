package client

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/metadata"

	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/phasesig"
	"github.com/netbirdio/netbird/shared/relay/messages"
	sigProto "github.com/netbirdio/netbird/shared/signal/proto"
	"github.com/netbirdio/netbird/signal/server"
)

func setAlignedRequest(t *testing.T, period time.Duration, ok bool) {
	t.Helper()
	prev := alignedRequest
	alignedRequest = func() (time.Duration, bool) { return period, ok }
	t.Cleanup(func() { alignedRequest = prev })
}

// recordingSignalServer records the stream-open metadata. With stripAnswer it
// acts like a server from before the aligned heartbeat: it never answers.
type recordingSignalServer struct {
	*server.Server
	stripAnswer atomic.Bool

	mu       sync.Mutex
	incoming []metadata.MD
}

type strippingStream struct {
	sigProto.SignalExchange_ConnectStreamServer
}

func (s strippingStream) SendHeader(md metadata.MD) error {
	md = md.Copy()
	delete(md, alignedhb.MetadataKey)
	return s.SignalExchange_ConnectStreamServer.SendHeader(md)
}

func (s *recordingSignalServer) ConnectStream(stream sigProto.SignalExchange_ConnectStreamServer) error {
	md, _ := metadata.FromIncomingContext(stream.Context())
	s.mu.Lock()
	s.incoming = append(s.incoming, md.Copy())
	s.mu.Unlock()
	if s.stripAnswer.Load() {
		return s.Server.ConnectStream(strippingStream{stream})
	}
	return s.Server.ConnectStream(stream)
}

// streams returns the number of streams opened so far.
func (s *recordingSignalServer) streams() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.incoming)
}

func (s *recordingSignalServer) lastRequest() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.incoming) == 0 {
		return nil
	}
	return s.incoming[len(s.incoming)-1].Get(alignedhb.MetadataKey)
}

func connectAlignedTestClient(t *testing.T, srv *recordingSignalServer) (*GrpcClient, wgtypes.Key) {
	t.Helper()
	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	return connectAlignedTestClientWithKey(t, srv, key), key
}

func connectAlignedTestClientWithKey(t *testing.T, srv *recordingSignalServer, key wgtypes.Key) *GrpcClient {
	t.Helper()
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

	connected := make(chan struct{})
	go func() {
		client.WaitStreamConnected(ctx)
		close(connected)
	}()
	select {
	case <-connected:
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not connect")
	}
	return client
}

func newRecordingSignalServer(t *testing.T, stripAnswer bool) *recordingSignalServer {
	t.Helper()
	backing, err := server.NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)
	verifier, err := phasesig.NewVerifier(testPhaseSecret)
	require.NoError(t, err)
	backing.SetPhaseVerifier(verifier)
	srv := &recordingSignalServer{Server: backing}
	srv.stripAnswer.Store(stripAnswer)
	return srv
}

const testPhaseSecret = "relay-auth-secret"

// storeTestSignedPhase stores the phase Management would sign for key, as the
// Management client does when the Sync answer arrives.
func storeTestSignedPhase(t *testing.T, key wgtypes.Key, period time.Duration) alignedhb.SignedPhase {
	t.Helper()
	peer := messages.HashID(key.PublicKey().String())
	signer, err := phasesig.NewSigner(testPhaseSecret)
	require.NoError(t, err)
	sp, err := signer.SignedPhase(peer, period, time.Now())
	require.NoError(t, err)
	alignedhb.StoreSignedPhase(peer, period, sp)
	t.Cleanup(func() { alignedhb.ClearSignedPhase(peer) })
	return sp
}

func TestAlignedClientOnNewSignalServer(t *testing.T) {
	setAlignedRequest(t, 60*time.Second, true)
	srv := newRecordingSignalServer(t, false)
	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	sp := storeTestSignedPhase(t, key, 60*time.Second)
	client := connectAlignedTestClientWithKey(t, srv, key)

	want := alignedhb.StreamRequest{Period: 60 * time.Second, Signed: &sp}
	assert.Equal(t, []string{want.Value()}, srv.lastRequest(), "the stream open must carry the signed phase")
	got, ok := client.alignedHeartbeat()
	require.True(t, ok, "the new server must answer")
	assert.Equal(t, alignedhb.Answer{Period: 60 * time.Second, Phase: sp.Phase}, got,
		"Signal must tick on the phase Management signed")
}

func TestAlignedClientSendsSignedPeriod(t *testing.T) {
	// The client asks for 60 s but Management confirmed and signed 120 s. The
	// stream must carry the signed period, else the signature cannot verify.
	setAlignedRequest(t, 60*time.Second, true)
	srv := newRecordingSignalServer(t, false)
	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	sp := storeTestSignedPhase(t, key, 120*time.Second)
	client := connectAlignedTestClientWithKey(t, srv, key)

	got, ok := client.alignedHeartbeat()
	require.True(t, ok, "the new server must answer")
	assert.Equal(t, alignedhb.Answer{Period: 120 * time.Second, Phase: sp.Phase}, got)
}

func TestAlignedClientWithoutSignedPhase(t *testing.T) {
	// Before the first Management answer the client has no signed phase. The
	// stream opens with the period only and stays stock.
	setAlignedRequest(t, 60*time.Second, true)
	srv := newRecordingSignalServer(t, false)
	client, _ := connectAlignedTestClient(t, srv)

	assert.Equal(t, []string{"period=60"}, srv.lastRequest(), "the stream open must carry the period")
	_, ok := client.alignedHeartbeat()
	assert.False(t, ok, "without a signed phase the stream stays stock")
	assert.Equal(t, StreamConnected, client.GetStatus(), "the missing answer must not break registration")
}

func TestAlignedClientIgnoresPhaseOfOtherPeer(t *testing.T) {
	// A phase stored for another key, as after an account switch, must not be
	// sent.
	setAlignedRequest(t, 60*time.Second, true)
	other, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	storeTestSignedPhase(t, other, 60*time.Second)
	srv := newRecordingSignalServer(t, false)
	client, _ := connectAlignedTestClient(t, srv)

	assert.Equal(t, []string{"period=60"}, srv.lastRequest(), "the phase of another peer must not be sent")
	_, ok := client.alignedHeartbeat()
	assert.False(t, ok)
}

func TestAlignedClientOnOldSignalServer(t *testing.T) {
	setAlignedRequest(t, 60*time.Second, true)
	srv := newRecordingSignalServer(t, true)
	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	sp := storeTestSignedPhase(t, key, 60*time.Second)
	client := connectAlignedTestClientWithKey(t, srv, key)

	want := alignedhb.StreamRequest{Period: 60 * time.Second, Signed: &sp}
	assert.Equal(t, []string{want.Value()}, srv.lastRequest(), "the stream open must carry the signed phase")
	_, ok := client.alignedHeartbeat()
	assert.False(t, ok, "without an answer the stream stays stock")
	assert.Equal(t, StreamConnected, client.GetStatus(), "the missing answer must not break registration")
}

func TestStockClientSendsNoRequest(t *testing.T) {
	setAlignedRequest(t, 0, false)
	srv := newRecordingSignalServer(t, false)
	client, _ := connectAlignedTestClient(t, srv)

	assert.Empty(t, srv.lastRequest(), "a client that does not ask sends no metadata")
	_, ok := client.alignedHeartbeat()
	assert.False(t, ok)
}

func TestAlignedAnswerFromHeader(t *testing.T) {
	_, _, ok := alignedAnswerFromHeader(metadata.MD{})
	assert.False(t, ok, "no key: old server")
	_, _, ok = alignedAnswerFromHeader(metadata.Pairs(alignedhb.MetadataKey, "period=60;phase=60000"))
	assert.False(t, ok, "phase outside the period")
	_, _, ok = alignedAnswerFromHeader(metadata.Pairs(alignedhb.MetadataKey, "period=x"))
	assert.False(t, ok, "unreadable")

	got, aligned, ok := alignedAnswerFromHeader(metadata.Pairs(alignedhb.MetadataKey, "period=60"))
	require.True(t, ok, "a period alone is an answer")
	assert.False(t, aligned, "without a phase the stream stays stock")
	assert.Equal(t, 60*time.Second, got.Period, "period")

	got, aligned, ok = alignedAnswerFromHeader(metadata.Pairs(alignedhb.MetadataKey, "period=60;phase=5"))
	require.True(t, ok)
	assert.True(t, aligned)
	assert.Equal(t, alignedhb.Answer{Period: 60 * time.Second, Phase: 5 * time.Millisecond}, got)
}

// The client clamps the period Signal confirms to its own limits, so a buggy
// or hostile server cannot make the device wake every second.
func TestAlignedAnswerFromHeaderClampsPeriod(t *testing.T) {
	for value, want := range map[string]alignedhb.Answer{
		"period=1;phase=500":       {Period: 30 * time.Second, Phase: 500 * time.Millisecond},
		"period=1000;phase=400000": {Period: 300 * time.Second, Phase: 100 * time.Second},
		"period=60;phase=5000":     {Period: 60 * time.Second, Phase: 5 * time.Second},
	} {
		got, aligned, ok := alignedAnswerFromHeader(metadata.Pairs(alignedhb.MetadataKey, value))
		require.True(t, ok, "value %q", value)
		assert.True(t, aligned, "value %q", value)
		assert.Equal(t, want, got, "value %q", value)
	}

	got, aligned, ok := alignedAnswerFromHeader(metadata.Pairs(alignedhb.MetadataKey, "period=1"))
	require.True(t, ok, "a period alone is an answer")
	assert.False(t, aligned, "without a phase the stream stays stock")
	assert.Equal(t, 30*time.Second, got.Period, "1s is raised to 30s")
}
