package grpc

import (
	"context"
	"testing"

	pb "github.com/golang/protobuf/proto" //nolint
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

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

// The stream encrypts with a shared key it precomputes once. The stock client
// decrypt path must read every send, each with its own nonce, and the
// envelope must keep naming the server public key.
func TestSendUpdate_PrecomputedDecryptsWithStockPath(t *testing.T) {
	ctrl := gomock.NewController(t)
	secretsManager := NewMockSecretsManager(ctrl)
	srv := &chanSyncSender{ctx: context.Background(), sent: make(chan *proto.EncryptedMessage, 4)}

	peerPriv := mustGenerateKey(t)
	srvKey := mustGenerateKey(t)
	secretsManager.EXPECT().GetWGKey().AnyTimes().Return(srvKey, nil)

	pu := &PeerUpdateHandler{
		peerKey:        peerPriv.PublicKey(),
		secretsManager: secretsManager,
		encrypter:      &streamEncrypter{},
		srv:            srv,
		cleanupFunc:    func() {},
	}

	updates := []*network_map.UpdateMessage{
		{Update: &proto.SyncResponse{}},
		{Update: &proto.SyncResponse{Version: 7}},
		{Update: &proto.SyncResponse{Version: 8}},
	}
	bodies := make(map[string]bool)
	for i, update := range updates {
		require.NoError(t, pu.SendUpdate(context.Background(), update), "send %d", i)
		select {
		case msg := <-srv.sent:
			assert.Equal(t, srvKey.PublicKey().String(), msg.GetWgPubKey(), "send %d names the server key", i)
			assert.False(t, bodies[string(msg.GetBody())], "send %d reuses a nonce", i)
			bodies[string(msg.GetBody())] = true
			resp := &proto.SyncResponse{}
			require.NoError(t, encryption.DecryptMessage(srvKey.PublicKey(), peerPriv, msg.GetBody(), resp),
				"send %d must decrypt with the stock client path", i)
			assert.True(t, pb.Equal(update.Update, resp), "send %d payload", i)
		default:
			t.Fatalf("send %d was not written to the stream", i)
		}
	}
}

// A server key change mid-stream derives a new shared key and names the new
// public key: the peer decrypts with the new key, not the cached one.
func TestSendUpdate_ServerKeyChange(t *testing.T) {
	ctrl := gomock.NewController(t)
	secretsManager := NewMockSecretsManager(ctrl)
	srv := &chanSyncSender{ctx: context.Background(), sent: make(chan *proto.EncryptedMessage, 2)}

	peerPriv := mustGenerateKey(t)
	firstKey := mustGenerateKey(t)
	secondKey := mustGenerateKey(t)
	gomock.InOrder(
		secretsManager.EXPECT().GetWGKey().Return(firstKey, nil),
		secretsManager.EXPECT().GetWGKey().Return(secondKey, nil),
	)

	pu := &PeerUpdateHandler{
		peerKey:        peerPriv.PublicKey(),
		secretsManager: secretsManager,
		encrypter:      &streamEncrypter{},
		srv:            srv,
		cleanupFunc:    func() {},
	}

	for i, srvKey := range []wgtypes.Key{firstKey, secondKey} {
		require.NoError(t, pu.SendUpdate(context.Background(), &network_map.UpdateMessage{Update: &proto.SyncResponse{}}), "send %d", i)
		select {
		case msg := <-srv.sent:
			assert.Equal(t, srvKey.PublicKey().String(), msg.GetWgPubKey(), "send %d names the current server key", i)
			resp := &proto.SyncResponse{}
			require.NoError(t, encryption.DecryptMessage(srvKey.PublicKey(), peerPriv, msg.GetBody(), resp),
				"send %d must decrypt with the current server key", i)
		default:
			t.Fatalf("send %d was not written to the stream", i)
		}
	}
}

func BenchmarkEncryptMessageUncached(b *testing.B) {
	peerPriv, err := wgtypes.GenerateKey()
	require.NoError(b, err)
	srvKey, err := wgtypes.GenerateKey()
	require.NoError(b, err)
	peerKey := peerPriv.PublicKey()
	encrypter := encryption.DefaultEncrypter{}
	msg := &proto.SyncResponse{}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := encrypter.EncryptMessage(peerKey, srvKey, msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptMessagePrecomputed(b *testing.B) {
	peerPriv, err := wgtypes.GenerateKey()
	require.NoError(b, err)
	srvKey, err := wgtypes.GenerateKey()
	require.NoError(b, err)
	peerKey := peerPriv.PublicKey()
	encrypter := &streamEncrypter{}
	msg := &proto.SyncResponse{}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := encrypter.EncryptMessage(peerKey, srvKey, msg); err != nil {
			b.Fatal(err)
		}
	}
}
