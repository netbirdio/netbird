package client

import (
	"bytes"
	"io"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// fakeSyncStream replays prepared messages, then returns io.EOF.
type fakeSyncStream struct {
	grpc.ClientStream
	msgs []*proto.EncryptedMessage
}

func (f *fakeSyncStream) Recv() (*proto.EncryptedMessage, error) {
	if len(f.msgs) == 0 {
		return nil, io.EOF
	}
	m := f.msgs[0]
	f.msgs = f.msgs[1:]
	return m, nil
}

func encryptForClient(t *testing.T, serverKey, clientKey wgtypes.Key, msg *proto.SyncResponse) *proto.EncryptedMessage {
	t.Helper()
	body, err := encryption.EncryptMessage(clientKey.PublicKey(), serverKey, msg)
	require.NoError(t, err)
	return &proto.EncryptedMessage{WgPubKey: serverKey.PublicKey().String(), Body: body}
}

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevLevel := log.StandardLogger().Out, log.GetLevel()
	log.SetOutput(&buf)
	log.SetLevel(log.DebugLevel)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetLevel(prevLevel)
	})
	return &buf
}

func heartbeatResponse() *proto.SyncResponse {
	return &proto.SyncResponse{Heartbeat: &proto.Heartbeat{}}
}

func TestReceiveUpdatesEvents_Heartbeat(t *testing.T) {
	serverKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	clientKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	c := &GrpcClient{key: clientKey}

	t.Run("heartbeat skips handler and logs nothing at debug", func(t *testing.T) {
		buf := captureLogs(t)
		stream := &fakeSyncStream{msgs: []*proto.EncryptedMessage{
			encryptForClient(t, serverKey, clientKey, heartbeatResponse()),
			encryptForClient(t, serverKey, clientKey, heartbeatResponse()),
		}}

		calls := 0
		err := c.receiveUpdatesEvents(stream, serverKey.PublicKey(), func(*proto.SyncResponse) error {
			calls++
			return nil
		})

		assert.ErrorIs(t, err, io.EOF, "loop should run until the stream ends")
		assert.Equal(t, 0, calls, "handler must not be called for heartbeats")
		assert.NotContains(t, buf.String(), "update message", "heartbeats must not log at debug or above")
	})

	t.Run("real response after heartbeat still reaches handler", func(t *testing.T) {
		buf := captureLogs(t)
		update := &proto.SyncResponse{NetbirdConfig: &proto.NetbirdConfig{}}
		stream := &fakeSyncStream{msgs: []*proto.EncryptedMessage{
			encryptForClient(t, serverKey, clientKey, heartbeatResponse()),
			encryptForClient(t, serverKey, clientKey, update),
		}}

		var got []*proto.SyncResponse
		err := c.receiveUpdatesEvents(stream, serverKey.PublicKey(), func(m *proto.SyncResponse) error {
			got = append(got, m)
			return nil
		})

		assert.ErrorIs(t, err, io.EOF, "loop should run until the stream ends")
		require.Len(t, got, 1, "only the real response should reach the handler")
		assert.NotNil(t, got[0].GetNetbirdConfig(), "handler should get the decrypted real response")
		assert.Equal(t, 1, strings.Count(buf.String(), "got an update message"), "real response should log at debug once")
	})

	// An empty response is not a heartbeat. It reaches the handler as it does
	// on a stock client.
	t.Run("empty response reaches handler", func(t *testing.T) {
		stream := &fakeSyncStream{msgs: []*proto.EncryptedMessage{
			encryptForClient(t, serverKey, clientKey, &proto.SyncResponse{}),
		}}

		calls := 0
		err := c.receiveUpdatesEvents(stream, serverKey.PublicKey(), func(*proto.SyncResponse) error {
			calls++
			return nil
		})

		assert.ErrorIs(t, err, io.EOF, "loop should run until the stream ends")
		assert.Equal(t, 1, calls, "an empty response must reach the handler")
	})
}
