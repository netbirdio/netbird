package client

import (
	"context"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"

	nbgrpc "github.com/netbirdio/netbird/client/grpc"
	"github.com/netbirdio/netbird/client/system"
	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

func setAlignedRequest(t *testing.T, period time.Duration, ok bool) {
	t.Helper()
	prev := alignedRequest
	alignedRequest = func() (time.Duration, bool) { return period, ok }
	t.Cleanup(func() { alignedRequest = prev })
}

func TestPeerCapabilitiesAlignedHeartbeat(t *testing.T) {
	setAlignedRequest(t, 0, false)
	assert.NotContains(t, peerCapabilities(system.Info{}), proto.PeerCapability_PeerCapabilityAlignedHeartbeat,
		"a client that does not ask must not advertise the capability")

	setAlignedRequest(t, 60*time.Second, true)
	assert.Contains(t, peerCapabilities(system.Info{}), proto.PeerCapability_PeerCapabilityAlignedHeartbeat,
		"a client that asks must advertise the capability")
}

// syncCapture records the Sync request and returns a stream that ends at once.
type syncCapture struct {
	proto.ManagementServiceClient
	req *proto.EncryptedMessage
}

func (s *syncCapture) Sync(_ context.Context, in *proto.EncryptedMessage, _ ...grpc.CallOption) (proto.ManagementService_SyncClient, error) {
	s.req = in
	return &fakeSyncStream{}, nil
}

func sentSyncRequest(t *testing.T, c *GrpcClient, serverKey wgtypes.Key) *proto.SyncRequest {
	t.Helper()
	capture := &syncCapture{}
	c.conn.Swap(nil, capture, 0)
	_, err := c.connectToSyncStream(context.Background(), serverKey.PublicKey(), &system.Info{})
	require.NoError(t, err)
	require.NotNil(t, capture.req, "Sync must be called")
	req := &proto.SyncRequest{}
	require.NoError(t, encryption.DecryptMessage(c.key.PublicKey(), serverKey, capture.req.Body, req))
	return req
}

func TestConnectToSyncStreamAsksForAlignedHeartbeat(t *testing.T) {
	serverKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	clientKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	c := &GrpcClient{key: clientKey}

	setAlignedRequest(t, 60*time.Second, true)
	c.alignedAnswer.Store(&alignedhb.Answer{Period: time.Minute})
	req := sentSyncRequest(t, c, serverKey)
	assert.Equal(t, uint32(60), req.GetAlignedHeartbeat().GetPeriodSeconds(), "the request must carry the period")
	assert.True(t, slices.Contains(req.GetMeta().GetCapabilities(), proto.PeerCapability_PeerCapabilityAlignedHeartbeat),
		"the request meta must carry the capability")
	_, ok := c.alignedHeartbeat()
	assert.False(t, ok, "a new stream must start without an answer")

	setAlignedRequest(t, 0, false)
	req = sentSyncRequest(t, c, serverKey)
	assert.Nil(t, req.GetAlignedHeartbeat(), "a client that does not ask sends no period")
	assert.False(t, slices.Contains(req.GetMeta().GetCapabilities(), proto.PeerCapability_PeerCapabilityAlignedHeartbeat),
		"a client that does not ask sends no capability")
}

func syncWithAligned(cfg *proto.AlignedHeartbeatConfig) *proto.SyncResponse {
	return &proto.SyncResponse{PeerConfig: &proto.PeerConfig{AlignedHeartbeat: cfg}}
}

func TestReceiveUpdatesEventsRecordsAlignedAnswer(t *testing.T) {
	serverKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	clientKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	on := &proto.AlignedHeartbeatConfig{Enabled: true, PeriodSeconds: 60, PhaseMillis: 4321}

	run := func(t *testing.T, c *GrpcClient, msgs ...*proto.SyncResponse) int {
		t.Helper()
		stream := &fakeSyncStream{}
		for _, m := range msgs {
			stream.msgs = append(stream.msgs, encryptForClient(t, serverKey, clientKey, m))
		}
		calls := 0
		err := c.receiveUpdatesEvents(stream, serverKey.PublicKey(), func(*proto.SyncResponse) error {
			calls++
			return nil
		})
		require.ErrorIs(t, err, io.EOF)
		return calls
	}

	t.Run("answer on the first response", func(t *testing.T) {
		setAlignedRequest(t, 60*time.Second, true)
		c := &GrpcClient{key: clientKey}
		calls := run(t, c, syncWithAligned(on))
		got, ok := c.alignedHeartbeat()
		require.True(t, ok, "the answer must be recorded")
		assert.Equal(t, alignedhb.Answer{Period: 60 * time.Second, Phase: 4321 * time.Millisecond}, got)
		assert.Equal(t, 1, calls, "the response must still reach the handler")
	})

	t.Run("legacy network map peer config", func(t *testing.T) {
		setAlignedRequest(t, 60*time.Second, true)
		c := &GrpcClient{key: clientKey}
		run(t, c, &proto.SyncResponse{NetworkMap: &proto.NetworkMap{PeerConfig: &proto.PeerConfig{AlignedHeartbeat: on}}})
		_, ok := c.alignedHeartbeat()
		assert.True(t, ok, "the answer under the network map must be recorded")
	})

	t.Run("later update without the field keeps the answer", func(t *testing.T) {
		setAlignedRequest(t, 60*time.Second, true)
		c := &GrpcClient{key: clientKey}
		run(t, c, syncWithAligned(on), &proto.SyncResponse{PeerConfig: &proto.PeerConfig{Address: "100.64.0.2/16"}})
		_, ok := c.alignedHeartbeat()
		assert.True(t, ok, "a peer config without the field must not clear the answer")
	})

	t.Run("disabled answer turns it off", func(t *testing.T) {
		setAlignedRequest(t, 60*time.Second, true)
		c := &GrpcClient{key: clientKey}
		run(t, c, syncWithAligned(on), syncWithAligned(&proto.AlignedHeartbeatConfig{Enabled: false}))
		_, ok := c.alignedHeartbeat()
		assert.False(t, ok, "enabled false must turn it off")
	})

	t.Run("invalid answer is ignored", func(t *testing.T) {
		setAlignedRequest(t, 60*time.Second, true)
		c := &GrpcClient{key: clientKey}
		run(t, c, syncWithAligned(&proto.AlignedHeartbeatConfig{Enabled: true, PeriodSeconds: 60, PhaseMillis: 60000}))
		_, ok := c.alignedHeartbeat()
		assert.False(t, ok, "a phase outside the period must not turn it on")
		run(t, c, syncWithAligned(&proto.AlignedHeartbeatConfig{Enabled: true}))
		_, ok = c.alignedHeartbeat()
		assert.False(t, ok, "a zero period must not turn it on")
	})

	t.Run("old server sends no answer", func(t *testing.T) {
		setAlignedRequest(t, 60*time.Second, true)
		c := &GrpcClient{key: clientKey}
		run(t, c, &proto.SyncResponse{PeerConfig: &proto.PeerConfig{Address: "100.64.0.2/16"}})
		_, ok := c.alignedHeartbeat()
		assert.False(t, ok, "without an answer the client stays stock")
	})

	t.Run("client that did not ask ignores the field", func(t *testing.T) {
		setAlignedRequest(t, 0, false)
		c := &GrpcClient{key: clientKey}
		run(t, c, syncWithAligned(on))
		_, ok := c.alignedHeartbeat()
		assert.False(t, ok, "an unasked answer must be ignored")
	})
}

func TestReceiveUpdatesEventsStoresSignedPhase(t *testing.T) {
	serverKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	clientKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	peer := messages.HashID(clientKey.PublicKey().String())
	t.Cleanup(func() { alignedhb.ClearSignedPhase(peer) })
	setAlignedRequest(t, 60*time.Second, true)

	run := func(t *testing.T, msgs ...*proto.SyncResponse) {
		t.Helper()
		stream := &fakeSyncStream{}
		for _, m := range msgs {
			stream.msgs = append(stream.msgs, encryptForClient(t, serverKey, clientKey, m))
		}
		c := &GrpcClient{key: clientKey}
		err := c.receiveUpdatesEvents(stream, serverKey.PublicKey(), func(*proto.SyncResponse) error { return nil })
		require.ErrorIs(t, err, io.EOF)
	}
	signed := &proto.AlignedHeartbeatConfig{
		Enabled: true, PeriodSeconds: 60, PhaseMillis: 4321,
		PhaseSignature: []byte{9, 8, 7}, PhaseDay: 20405,
	}

	run(t, syncWithAligned(signed))
	period, sp, ok := alignedhb.LoadSignedPhase(peer)
	require.True(t, ok, "the signed phase must be stored for the Signal and relay clients")
	assert.Equal(t, time.Minute, period, "period the phase was signed for")
	assert.Equal(t, alignedhb.SignedPhase{Phase: 4321 * time.Millisecond, Day: 20405, Signature: []byte{9, 8, 7}}, sp)

	// A new stream that ends before any answer, as during a Management outage,
	// must keep the phase so Signal and relay streams that reopen still get it.
	run(t)
	_, _, ok = alignedhb.LoadSignedPhase(peer)
	assert.True(t, ok, "the signed phase must outlive the Management stream")

	run(t, syncWithAligned(&proto.AlignedHeartbeatConfig{Enabled: true, PeriodSeconds: 60, PhaseMillis: 1}))
	_, sp, _ = alignedhb.LoadSignedPhase(peer)
	assert.Equal(t, 4321*time.Millisecond, sp.Phase, "an unsigned answer from an older Management must not replace the signed phase")

	run(t, syncWithAligned(&proto.AlignedHeartbeatConfig{Enabled: true, PeriodSeconds: 60, PhaseMillis: 1, PhaseSignature: make([]byte, 65)}))
	_, sp, _ = alignedhb.LoadSignedPhase(peer)
	assert.Equal(t, 4321*time.Millisecond, sp.Phase, "an oversized signature must be ignored")

	run(t, syncWithAligned(&proto.AlignedHeartbeatConfig{Enabled: false}))
	_, _, ok = alignedhb.LoadSignedPhase(peer)
	assert.False(t, ok, "Management turning the heartbeat off must drop the signed phase")
}

// The first heartbeat after the day change carries the phase of the new day.
// The client stores it, so Signal and relay get it, and keeps the heartbeat out
// of the network map handler.
func TestReceiveUpdatesEventsNewDayPhase(t *testing.T) {
	serverKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	clientKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	peer := messages.HashID(clientKey.PublicKey().String())
	t.Cleanup(func() { alignedhb.ClearSignedPhase(peer) })
	setAlignedRequest(t, 60*time.Second, true)

	today := &proto.AlignedHeartbeatConfig{Enabled: true, PeriodSeconds: 60, PhaseMillis: 4321, PhaseSignature: []byte{1}, PhaseDay: 20405}
	tomorrow := &proto.AlignedHeartbeatConfig{Enabled: true, PeriodSeconds: 60, PhaseMillis: 777, PhaseSignature: []byte{2}, PhaseDay: 20406}
	stream := &fakeSyncStream{msgs: []*proto.EncryptedMessage{
		encryptForClient(t, serverKey, clientKey, syncWithAligned(today)),
		encryptForClient(t, serverKey, clientKey, &proto.SyncResponse{Heartbeat: &proto.Heartbeat{}}),
	}}
	c := &GrpcClient{key: clientKey}
	calls := 0
	handler := func(*proto.SyncResponse) error {
		calls++
		return nil
	}
	require.ErrorIs(t, c.receiveUpdatesEvents(stream, serverKey.PublicKey(), handler), io.EOF)
	before, ok := alignedhb.LoadStoredPhase(peer)
	require.True(t, ok)
	changed := alignedhb.SignedPhaseChanged()

	stream = &fakeSyncStream{msgs: []*proto.EncryptedMessage{
		encryptForClient(t, serverKey, clientKey, &proto.SyncResponse{Heartbeat: &proto.Heartbeat{Config: tomorrow}}),
	}}
	require.ErrorIs(t, c.receiveUpdatesEvents(stream, serverKey.PublicKey(), handler), io.EOF)

	after, ok := alignedhb.LoadStoredPhase(peer)
	require.True(t, ok)
	assert.Equal(t, alignedhb.SignedPhase{Phase: 777 * time.Millisecond, Day: 20406, Signature: []byte{2}}, after.Signed,
		"the phase of the new day is stored")
	assert.Greater(t, after.Seq, before.Seq, "the new phase is newer for the Signal and relay streams")
	select {
	case <-changed:
	default:
		t.Fatal("the Signal and relay streams must be woken")
	}
	got, ok := c.alignedHeartbeat()
	require.True(t, ok)
	assert.Equal(t, alignedhb.Answer{Period: time.Minute, Phase: 777 * time.Millisecond}, got, "Management ticks on the new phase")
	assert.Equal(t, 1, calls, "heartbeats never reach the network map handler")
}

// The client clamps the period Management confirms to its own limits. A
// clamped answer carries no signed phase: the signature covers the period
// Management sent, so Signal and relay would reject it.
func TestAnswerFromConfigClampsPeriod(t *testing.T) {
	sig := make([]byte, 32)
	for name, tc := range map[string]struct {
		cfg    *proto.AlignedHeartbeatConfig
		want   alignedhb.Answer
		signed bool
	}{
		"1s": {
			cfg:  &proto.AlignedHeartbeatConfig{Enabled: true, PeriodSeconds: 1, PhaseMillis: 500, PhaseSignature: sig, PhaseDay: 20405},
			want: alignedhb.Answer{Period: 30 * time.Second, Phase: 500 * time.Millisecond},
		},
		"1000s": {
			cfg:  &proto.AlignedHeartbeatConfig{Enabled: true, PeriodSeconds: 1000, PhaseMillis: 400000, PhaseSignature: sig, PhaseDay: 20405},
			want: alignedhb.Answer{Period: 300 * time.Second, Phase: 100 * time.Second},
		},
		"60s": {
			cfg:    &proto.AlignedHeartbeatConfig{Enabled: true, PeriodSeconds: 60, PhaseMillis: 4321, PhaseSignature: sig, PhaseDay: 20405},
			want:   alignedhb.Answer{Period: 60 * time.Second, Phase: 4321 * time.Millisecond},
			signed: true,
		},
	} {
		answer, signed, err := answerFromConfig(tc.cfg)
		require.NoError(t, err, name)
		require.NotNil(t, answer, name)
		assert.Equal(t, tc.want, *answer, "%s: answer", name)
		assert.Equal(t, tc.signed, signed != nil, "%s: signed phase kept only without a clamp", name)
	}
}

// The TCP keepalive of the Management connection follows the answer of the
// Sync stream: aligned idle once confirmed, stock for a stock answer and for a
// new stream.
func TestAlignedAnswerSetsTCPKeepAlive(t *testing.T) {
	serverKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	clientKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	c := &GrpcClient{key: clientKey}
	setAlignedRequest(t, 60*time.Second, true)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	grpcSrv := grpc.NewServer()
	go func() { _ = grpcSrv.Serve(ln) }()
	t.Cleanup(grpcSrv.Stop)
	conn, err := grpc.NewClient("passthrough:///"+ln.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		nbgrpc.WithDialHooks(nil, &c.tcpKeepAlive, nil))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	conn.Connect()
	require.Eventually(t, func() bool { return conn.GetState() == connectivity.Ready },
		5*time.Second, 10*time.Millisecond, "the loopback dial must reach the server")

	c.applyAlignedConfig(&proto.AlignedHeartbeatConfig{Enabled: true, PeriodSeconds: 60, PhaseMillis: 1000})
	assert.Equal(t, time.Minute, c.tcpKeepAlive.Applied(), "an aligned answer must switch the keepalive")

	c.applyAlignedConfig(&proto.AlignedHeartbeatConfig{Enabled: false})
	assert.Zero(t, c.tcpKeepAlive.Applied(), "an off answer must restore the stock keepalive")

	c.applyAlignedConfig(&proto.AlignedHeartbeatConfig{Enabled: true, PeriodSeconds: 60, PhaseMillis: 1000})
	sentSyncRequest(t, c, serverKey)
	assert.Zero(t, c.tcpKeepAlive.Applied(), "a new stream must start with the stock keepalive")
}
