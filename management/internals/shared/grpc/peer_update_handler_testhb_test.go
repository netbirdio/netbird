package grpc

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	pb "github.com/golang/protobuf/proto" //nolint
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/shared/management/proto"
)

type chanSyncSender struct {
	ctx  context.Context
	sent chan *proto.EncryptedMessage
}

func (c *chanSyncSender) Send(m *proto.EncryptedMessage) error {
	c.sent <- m
	return nil
}

func (c *chanSyncSender) Context() context.Context { return c.ctx }

// testhb reads its env once per process, so the test runs itself in a child
// process with aligned mode and a 1s period.
func TestHandleUpdates_TestHeartbeatAligned(t *testing.T) {
	if os.Getenv("NB_TEST_HB_MODE") == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestHandleUpdates_TestHeartbeatAligned$", "-test.v")
		cmd.Env = append(os.Environ(), "NB_TEST_HB_MODE=aligned", "NB_TEST_HB_PERIOD_SEC=1")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
		return
	}

	ctrl := gomock.NewController(t)
	secretsManager := NewMockSecretsManager(ctrl)
	peerPriv := mustGenerateKey(t)
	srvKey := mustGenerateKey(t)
	secretsManager.EXPECT().GetWGKey().AnyTimes().Return(srvKey, nil)

	srvCtx, cancel := context.WithCancel(context.Background())
	srv := &chanSyncSender{ctx: srvCtx, sent: make(chan *proto.EncryptedMessage, 4)}

	pu := PeerUpdateHandler{
		peerKey:        peerPriv.PublicKey(),
		updates:        make(chan *network_map.UpdateMessage),
		secretsManager: secretsManager,
		encrypter:      encryption.DefaultEncrypter{},
		debouncer:      NewUpdateDebouncer(time.Second),
		srv:            srv,
		cleanupFunc:    func() {},
	}

	done := make(chan error, 1)
	go func() { done <- pu.HandleUpdates(srvCtx) }()

	var msg *proto.EncryptedMessage
	select {
	case msg = <-srv.sent:
	case <-time.After(3 * time.Second):
		t.Fatal("no heartbeat within 3s")
	}
	cancel()
	<-done

	assert.Equal(t, srvKey.PublicKey().String(), msg.WgPubKey, "heartbeat must carry the server public key")
	resp := &proto.SyncResponse{Version: 99}
	require.NoError(t, encryption.DecryptMessage(srvKey.PublicKey(), peerPriv, msg.Body, resp))
	assert.True(t, pb.Equal(&proto.SyncResponse{}, resp), "heartbeat must be an empty SyncResponse, got %v", resp)
}
