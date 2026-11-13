package grpc

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	pb "github.com/golang/protobuf/proto" //nolint
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/metadata"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/testhb"
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

// Dynamic mode: the heartbeat lands on the client phase plus the measured skew.
// A mute file entry stops the sends for a tick, removing it resumes them.
func TestHandleUpdates_TestHeartbeatDynamicMute(t *testing.T) {
	if os.Getenv("NB_TEST_HB_MODE") == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestHandleUpdates_TestHeartbeatDynamicMute$", "-test.v")
		cmd.Env = append(os.Environ(), "NB_TEST_HB_MODE=dynamic")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
		return
	}

	mutePath := filepath.Join(t.TempDir(), "mute")
	t.Setenv("NB_TEST_HB_MUTE_FILE", mutePath)

	assert.False(t, testHBClientSchedule(context.Background(), time.Now()).OK, "no metadata must give no schedule")

	arrival := time.Now()
	value := "p=500;period=2;t=" + strconv.FormatInt(arrival.UnixMilli()-100, 10)
	mdCtx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(testhb.MetadataKey, value))
	cs := testHBClientSchedule(mdCtx, arrival)
	require.True(t, cs.OK, "schedule from metadata")
	require.Equal(t, int64(100), cs.SkewMs, "skew")

	ctrl := gomock.NewController(t)
	secretsManager := NewMockSecretsManager(ctrl)
	secretsManager.EXPECT().GetWGKey().AnyTimes().Return(mustGenerateKey(t), nil)

	srvCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &chanSyncSender{ctx: srvCtx, sent: make(chan *proto.EncryptedMessage, 4)}
	pu := &PeerUpdateHandler{
		peerKey:        mustGenerateKey(t).PublicKey(),
		updates:        make(chan *network_map.UpdateMessage),
		secretsManager: secretsManager,
		encrypter:      encryption.DefaultEncrypter{},
		debouncer:      NewUpdateDebouncer(time.Second),
		srv:            srv,
		cleanupFunc:    func() {},
	}
	pu.WithTestHBSchedule(cs)

	done := make(chan error, 1)
	go func() { done <- pu.HandleUpdates(srvCtx) }()
	defer func() {
		cancel()
		<-done
	}()

	select {
	case <-srv.sent:
		got := time.Now().UnixMilli() % 2000
		assert.True(t, got >= 600 && got < 700, "heartbeat at ms %d mod 2000, want 600", got)
	case <-time.After(3 * time.Second):
		t.Fatal("no dynamic heartbeat within 3s")
	}

	require.NoError(t, os.WriteFile(mutePath, []byte("management\n"), 0o644))
	select {
	case <-srv.sent:
		t.Fatal("muted management sent a heartbeat")
	case <-time.After(2500 * time.Millisecond):
	}

	require.NoError(t, os.Remove(mutePath))
	select {
	case <-srv.sent:
	case <-time.After(2500 * time.Millisecond):
		t.Fatal("no heartbeat after unmute")
	}
}
