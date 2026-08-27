package grpc

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	pb "github.com/golang/protobuf/proto"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestSendPeerUpdates_FirstUpdate(t *testing.T) {
	ctrl := gomock.NewController(t)
	secretsManager := NewMockSecretsManager(ctrl)
	updateDebouncer := NewMockDebouncer(ctrl)
	syncSender := NewMocksyncSender(ctrl)

	pu := PeerUpdateHandler{
		peerKey:        mustGenerateKey(t),
		updates:        make(chan *network_map.UpdateMessage),
		secretsManager: secretsManager,
		encrypter:      testEncrypter{},
		debouncer:      updateDebouncer,
		srv:            syncSender,
		cleanupFunc:    func() {},
	}

	msg := network_map.UpdateMessage{
		Update: &proto.SyncResponse{Version: 1},
	}

	timeCh := make(chan time.Time)
	srvCtx, _ := context.WithCancel(context.TODO())
	srvKey := mustGenerateKey(t)
	// mock a first update, should send it right away
	updateDebouncer.EXPECT().ProcessUpdate(gomock.Eq(&msg)).Return(true)
	updateDebouncer.EXPECT().TimerChannel().AnyTimes().Return(timeCh)
	syncSender.EXPECT().Context().AnyTimes().Return(srvCtx)
	secretsManager.EXPECT().GetWGKey().Return(srvKey, nil)
	syncSender.EXPECT().Send(pbMatcher{x: &proto.EncryptedMessage{WgPubKey: srvKey.PublicKey().String(), Body: mustMarshal(t, &msg)}})
	updateDebouncer.EXPECT().Stop()

	var wg sync.WaitGroup
	wg.Go(func() { pu.HandleUpdates(context.TODO()) })
	pu.updates <- &msg
	close(pu.updates)
	wg.Wait()
}

func TestSendPeerUpdates_TimerUpdate(t *testing.T) {
	ctrl := gomock.NewController(t)
	secretsManager := NewMockSecretsManager(ctrl)
	updateDebouncer := NewMockDebouncer(ctrl)
	syncSender := NewMocksyncSender(ctrl)

	pu := PeerUpdateHandler{
		peerKey:        mustGenerateKey(t),
		updates:        make(chan *network_map.UpdateMessage),
		secretsManager: secretsManager,
		encrypter:      testEncrypter{},
		debouncer:      updateDebouncer,
		srv:            syncSender,
		cleanupFunc:    func() {},
	}

	msg := network_map.UpdateMessage{
		Update: &proto.SyncResponse{Version: 1},
	}

	timeCh := make(chan time.Time)
	srvCtx, _ := context.WithCancel(context.TODO())
	srvKey := mustGenerateKey(t)
	updateDebouncer.EXPECT().GetPendingUpdates().Return([]*network_map.UpdateMessage{&msg})
	updateDebouncer.EXPECT().TimerChannel().AnyTimes().Return(timeCh)
	syncSender.EXPECT().Context().AnyTimes().Return(srvCtx)
	secretsManager.EXPECT().GetWGKey().Return(srvKey, nil)
	syncSender.EXPECT().Send(pbMatcher{x: &proto.EncryptedMessage{WgPubKey: srvKey.PublicKey().String(), Body: mustMarshal(t, &msg)}})
	updateDebouncer.EXPECT().Stop()

	var wg sync.WaitGroup
	wg.Go(func() { pu.HandleUpdates(context.TODO()) })
	timeCh <- time.Now()
	close(pu.updates)
	wg.Wait()
}

func TestSendPeerUpdates_ServerContextDone(t *testing.T) {
	ctrl := gomock.NewController(t)
	secretsManager := NewMockSecretsManager(ctrl)
	updateDebouncer := NewMockDebouncer(ctrl)
	syncSender := NewMocksyncSender(ctrl)

	pu := PeerUpdateHandler{
		peerKey:        mustGenerateKey(t),
		updates:        make(chan *network_map.UpdateMessage),
		secretsManager: secretsManager,
		encrypter:      testEncrypter{},
		debouncer:      updateDebouncer,
		srv:            syncSender,
		cleanupFunc:    func() {},
	}

	timeCh := make(chan time.Time)
	srvCtx, cancel := context.WithCancel(context.TODO())
	updateDebouncer.EXPECT().TimerChannel().AnyTimes().Return(timeCh)
	syncSender.EXPECT().Context().AnyTimes().Return(srvCtx)
	updateDebouncer.EXPECT().Stop()

	var wg sync.WaitGroup
	wg.Go(func() { pu.HandleUpdates(context.TODO()) })
	cancel()
	wg.Wait()
}

func mustGenerateKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GenerateKey()
	assert.NoError(t, err)
	return k
}

func mustMarshal(t *testing.T, msg *network_map.UpdateMessage) []byte {
	t.Helper()
	r, err := pb.Marshal(msg.Update)
	assert.NoError(t, err)
	return r
}

type testEncrypter struct{}

func (testEncrypter) EncryptMessage(remotePubKey wgtypes.Key, ourPrivateKey wgtypes.Key, message pb.Message) ([]byte, error) {
	return pb.Marshal(message)
}

type pbMatcher struct {
	x pb.Message
}

func (pbm pbMatcher) Matches(x any) bool {
	msg, ok := x.(pb.Message)
	if !ok {
		return false
	}
	return pb.Equal(pbm.x, msg)
}

func (pbm pbMatcher) String() string {
	return fmt.Sprintf("is equal to %s (%T)", pbm.x, pbm.x)
}
