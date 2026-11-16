package client

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/shared/relay/messages"
	"github.com/netbirdio/netbird/shared/signal/proto"
)

// fakeConnectStream replays a fixed list of frames, then reports io.EOF.
type fakeConnectStream struct {
	grpc.ClientStream
	msgs []*proto.EncryptedMessage
}

func (f *fakeConnectStream) Send(*proto.EncryptedMessage) error { return nil }

func (f *fakeConnectStream) Recv() (*proto.EncryptedMessage, error) {
	if len(f.msgs) == 0 {
		return nil, io.EOF
	}
	msg := f.msgs[0]
	f.msgs = f.msgs[1:]
	return msg, nil
}

// The context is bounded so a frame that wrongly fills the one-slot worker pool
// makes the next hand-off give up instead of blocking the test forever.
func newHeartbeatTestClient(t *testing.T) *GrpcClient {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	decrypt := func(*proto.EncryptedMessage) (*proto.Message, error) { return nil, io.EOF }
	handle := func(*proto.Message) error { return nil }
	return &GrpcClient{
		ctx:              ctx,
		decryptionWorker: NewWorker(decrypt, handle),
	}
}

func heartbeatFrame() *proto.EncryptedMessage {
	return &proto.EncryptedMessage{RemoteKey: "peer", ServerHeartbeat: &proto.ServerHeartbeat{PhaseMillis: 1234}}
}

// The worker is not running, so whatever receive hands off stays in its
// one-slot pool. An empty pool means the frame never reached decryption.
func TestReceiveHeartbeatSkipsDecryption(t *testing.T) {
	c := newHeartbeatTestClient(t)
	stream := &fakeConnectStream{msgs: []*proto.EncryptedMessage{heartbeatFrame()}}

	err := c.receive(stream)
	require.ErrorIs(t, err, io.EOF)

	assert.NotZero(t, c.lastReceived.Load(), "heartbeat must refresh the receive timestamp")
	assert.Empty(t, c.decryptionWorker.encryptedMsgPool, "heartbeat must not reach the decryption worker")
}

func TestReceiveRealMessageAfterHeartbeat(t *testing.T) {
	c := newHeartbeatTestClient(t)
	peerMsg := &proto.EncryptedMessage{Key: "remote-peer", RemoteKey: "peer", Body: []byte{1}}
	stream := &fakeConnectStream{msgs: []*proto.EncryptedMessage{heartbeatFrame(), peerMsg}}

	err := c.receive(stream)
	require.ErrorIs(t, err, io.EOF)

	require.Len(t, c.decryptionWorker.encryptedMsgPool, 1, "real message must reach the decryption worker")
	got := <-c.decryptionWorker.encryptedMsgPool
	assert.Equal(t, peerMsg, got, "worker must get the real message, not the heartbeat")
}

// newAlignedTestClient returns a test client whose stream got the aligned
// heartbeat answer, so server heartbeats pass the gate.
func newAlignedTestClient(t *testing.T) *GrpcClient {
	c := newHeartbeatTestClient(t)
	c.phase.Store(newPhaseWriter(&fakeConnectStream{}, &c.streamSendMu, messages.PeerID{}, "", time.Minute, 0))
	return c
}

func goingAwayFrame() *proto.EncryptedMessage {
	return &proto.EncryptedMessage{RemoteKey: "peer", ServerHeartbeat: &proto.ServerHeartbeat{GoingAway: true}}
}

// A going-away frame must end the receive loop with errServerGoingAway, so the
// retry loop reconnects. It must not reach decryption and must not count as a
// heartbeat, since it carries no phase.
func TestReceiveGoingAwayEndsLoop(t *testing.T) {
	c := newAlignedTestClient(t)
	peerMsg := &proto.EncryptedMessage{Key: "remote-peer", RemoteKey: "peer", Body: []byte{1}}
	stream := &fakeConnectStream{msgs: []*proto.EncryptedMessage{goingAwayFrame(), peerMsg}}

	err := c.receive(stream)
	require.ErrorIs(t, err, errServerGoingAway)

	assert.Empty(t, c.decryptionWorker.encryptedMsgPool, "going-away must not reach the decryption worker")
	assert.Len(t, stream.msgs, 1, "receive must stop reading after going-away")
	assert.Nil(t, c.alignedAnswer.Load(), "going-away must not turn the aligned answer on")
}

// A going-away a peer forged must not end the stream: with a sender key on an
// aligned stream, or on a stream without the answer (desktop, stock server).
func TestReceiveForgedGoingAwayIgnored(t *testing.T) {
	withKey := goingAwayFrame()
	withKey.Key = "remote-peer"
	cases := map[string]struct {
		client *GrpcClient
		frame  *proto.EncryptedMessage
	}{
		"sender key on aligned stream": {newAlignedTestClient(t), withKey},
		"stream without answer":        {newHeartbeatTestClient(t), goingAwayFrame()},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			peerMsg := &proto.EncryptedMessage{Key: "remote-peer", RemoteKey: "peer", Body: []byte{1}}
			stream := &fakeConnectStream{msgs: []*proto.EncryptedMessage{tc.frame, peerMsg}}

			err := tc.client.receive(stream)
			require.ErrorIs(t, err, io.EOF, "a forged going-away must not end the stream")

			require.Len(t, tc.client.decryptionWorker.encryptedMsgPool, 1, "only the peerMsg message reaches the worker")
			assert.Equal(t, peerMsg, <-tc.client.decryptionWorker.encryptedMsgPool)
		})
	}
}

// The old test key has no meaning any more: such a frame is an ordinary peer
// message and goes to decryption, where a forged body fails.
func TestReceiveOldGoingAwayKeyIsPeerMessage(t *testing.T) {
	c := newAlignedTestClient(t)
	old := &proto.EncryptedMessage{Key: "netbird-test-going-away", RemoteKey: "peer"}
	stream := &fakeConnectStream{msgs: []*proto.EncryptedMessage{old}}

	err := c.receive(stream)
	require.ErrorIs(t, err, io.EOF)
	require.Len(t, c.decryptionWorker.encryptedMsgPool, 1, "the frame must go to the decryption worker")
}
