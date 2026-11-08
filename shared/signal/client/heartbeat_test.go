package client

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

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
	decrypt := func(*proto.EncryptedMessage) (*proto.Message, error) { return nil, nil }
	handle := func(*proto.Message) error { return nil }
	return &GrpcClient{
		ctx:              ctx,
		decryptionWorker: NewWorker(decrypt, handle),
	}
}

func heartbeatFrame() *proto.EncryptedMessage {
	return &proto.EncryptedMessage{Key: TestHeartbeatKey, RemoteKey: "peer"}
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
	real := &proto.EncryptedMessage{Key: "remote-peer", RemoteKey: "peer", Body: []byte{1}}
	stream := &fakeConnectStream{msgs: []*proto.EncryptedMessage{heartbeatFrame(), real}}

	err := c.receive(stream)
	require.ErrorIs(t, err, io.EOF)

	require.Len(t, c.decryptionWorker.encryptedMsgPool, 1, "real message must reach the decryption worker")
	got := <-c.decryptionWorker.encryptedMsgPool
	assert.Equal(t, real, got, "worker must get the real message, not the heartbeat")
}

// A going-away frame must end the receive loop with errServerGoingAway, so the
// retry loop reconnects, and must not reach decryption.
func TestReceiveGoingAwayEndsLoop(t *testing.T) {
	c := newHeartbeatTestClient(t)
	goingAway := &proto.EncryptedMessage{Key: TestGoingAwayKey, RemoteKey: "peer"}
	real := &proto.EncryptedMessage{Key: "remote-peer", RemoteKey: "peer", Body: []byte{1}}
	stream := &fakeConnectStream{msgs: []*proto.EncryptedMessage{goingAway, real}}

	err := c.receive(stream)
	require.ErrorIs(t, err, errServerGoingAway)

	assert.Empty(t, c.decryptionWorker.encryptedMsgPool, "going-away must not reach the decryption worker")
	assert.Len(t, stream.msgs, 1, "receive must stop reading after going-away")
}
