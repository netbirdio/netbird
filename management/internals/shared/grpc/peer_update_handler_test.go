package grpc

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	pb "github.com/golang/protobuf/proto" //nolint
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/shared/management/proto"
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
	srvCtx := context.TODO()
	srvKey := mustGenerateKey(t)
	// mock a first update, should send it right away
	updateDebouncer.EXPECT().ProcessUpdate(gomock.Eq(&msg)).Return(true)
	updateDebouncer.EXPECT().TimerChannel().AnyTimes().Return(timeCh)
	syncSender.EXPECT().Context().AnyTimes().Return(srvCtx)
	secretsManager.EXPECT().GetWGKey().Return(srvKey, nil)
	syncSender.EXPECT().Send(sentUpdateMatcher{wgPubKey: srvKey.PublicKey().String(), want: mustMarshal(t, &msg)})
	updateDebouncer.EXPECT().Stop()

	var wg sync.WaitGroup
	wg.Go(func() { pu.HandleUpdates(context.TODO()) }) //nolint:errcheck
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
	srvCtx := context.TODO()
	srvKey := mustGenerateKey(t)
	updateDebouncer.EXPECT().GetPendingUpdates().Return([]*network_map.UpdateMessage{&msg})
	updateDebouncer.EXPECT().TimerChannel().AnyTimes().Return(timeCh)
	syncSender.EXPECT().Context().AnyTimes().Return(srvCtx)
	secretsManager.EXPECT().GetWGKey().Return(srvKey, nil)
	syncSender.EXPECT().Send(sentUpdateMatcher{wgPubKey: srvKey.PublicKey().String(), want: mustMarshal(t, &msg)})
	updateDebouncer.EXPECT().Stop()

	var wg sync.WaitGroup
	wg.Go(func() { pu.HandleUpdates(context.TODO()) }) //nolint:errcheck
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
	wg.Go(func() { pu.HandleUpdates(context.TODO()) }) //nolint:errcheck
	cancel()
	wg.Wait()
}

func TestSendPeerUpdates_HeartbeatOnlyOnInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctrl := gomock.NewController(t)
		secretsManager := NewMockSecretsManager(ctrl)
		updateDebouncer := NewMockDebouncer(ctrl)
		syncSender := NewMocksyncSender(ctrl)

		var heartbeats atomic.Int32
		pu := PeerUpdateHandler{
			peerKey:        mustGenerateKey(t),
			updates:        make(chan *network_map.UpdateMessage),
			secretsManager: secretsManager,
			encrypter:      testEncrypter{},
			debouncer:      updateDebouncer,
			srv:            syncSender,
			cleanupFunc:    func() {},
			heartbeat:      func() { heartbeats.Add(1) },
		}

		msg := network_map.UpdateMessage{
			Update: &proto.SyncResponse{Version: 1},
		}

		srvCtx, cancel := context.WithCancel(context.Background())
		srvKey := mustGenerateKey(t)
		updateDebouncer.EXPECT().ProcessUpdate(gomock.Eq(&msg)).Return(true)
		updateDebouncer.EXPECT().TimerChannel().AnyTimes().Return(make(chan time.Time))
		syncSender.EXPECT().Context().AnyTimes().Return(srvCtx)
		secretsManager.EXPECT().GetWGKey().Return(srvKey, nil)
		syncSender.EXPECT().Send(gomock.Any())
		updateDebouncer.EXPECT().Stop()

		done := make(chan struct{})
		go func() {
			defer close(done)
			pu.HandleUpdates(context.Background()) //nolint:errcheck
		}()

		pu.updates <- &msg
		synctest.Wait()
		assert.Zero(t, heartbeats.Load(), "an update must not write a heartbeat")

		time.Sleep(nbpeer.HeartbeatInterval)
		synctest.Wait()
		assert.Equal(t, int32(1), heartbeats.Load(), "one heartbeat per interval")

		time.Sleep(nbpeer.HeartbeatInterval)
		synctest.Wait()
		assert.Equal(t, int32(2), heartbeats.Load(), "one heartbeat per interval")

		cancel()
		<-done
	})
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

// sentUpdateMatcher matches an update as sent: stamped with Management time, otherwise unchanged.
type sentUpdateMatcher struct {
	wgPubKey string
	want     []byte
}

func (m sentUpdateMatcher) Matches(x any) bool {
	msg, ok := x.(*proto.EncryptedMessage)
	if !ok || msg.GetWgPubKey() != m.wgPubKey {
		return false
	}
	var got, want proto.SyncResponse
	if pb.Unmarshal(msg.GetBody(), &got) != nil || pb.Unmarshal(m.want, &want) != nil {
		return false
	}
	if !got.GetManagementTime().IsValid() || time.Since(got.GetManagementTime().AsTime()) > time.Minute {
		return false
	}
	got.ManagementTime = nil
	return pb.Equal(&want, &got)
}

func (m sentUpdateMatcher) String() string {
	return "is the update stamped with Management time"
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
