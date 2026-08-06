package worker

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer/signaling"
	relayClient "github.com/netbirdio/netbird/shared/relay/client"
)

type RelayConnInfo struct {
	RelayedConn     net.Conn
	RosenpassPubKey []byte
	RosenpassAddr   string
}

type WorkerRelay struct {
	log            *log.Entry
	key            string
	isController   bool
	onConnReady    func(RelayConnInfo)
	onDisconnected func()
	relayManager   *relayClient.Manager

	relayedConn net.Conn
	relayLock   sync.Mutex

	relaySupportedOnRemotePeer atomic.Bool
}

func NewWorkerRelay(log *log.Entry, key string, isController bool, onConnReady func(RelayConnInfo), onDisconnected func(), relayManager *relayClient.Manager) *WorkerRelay {
	r := &WorkerRelay{
		log:            log,
		key:            key,
		isController:   isController,
		onConnReady:    onConnReady,
		onDisconnected: onDisconnected,
		relayManager:   relayManager,
	}
	return r
}

func (w *WorkerRelay) OnNewOffer(ctx context.Context, remoteOfferAnswer *signaling.OfferAnswer) {
	if !w.isRelaySupported(remoteOfferAnswer) {
		w.log.Infof("Relay is not supported by remote peer")
		w.relaySupportedOnRemotePeer.Store(false)
		return
	}
	w.relaySupportedOnRemotePeer.Store(true)

	// the relayManager will return with error in case if the connection has lost with relay server
	currentRelayAddress, _, err := w.relayManager.RelayInstanceAddress()
	if err != nil {
		w.log.Errorf("failed to handle new offer: %s", err)
		return
	}

	srv := w.preferredRelayServer(currentRelayAddress, remoteOfferAnswer.RelaySrvAddress)
	var serverIP netip.Addr
	if srv == remoteOfferAnswer.RelaySrvAddress {
		serverIP = remoteOfferAnswer.RelaySrvIP
	}

	relayedConn, err := w.relayManager.OpenConn(ctx, srv, w.key, serverIP)
	if err != nil {
		if errors.Is(err, relayClient.ErrConnAlreadyExists) {
			w.log.Debugf("handled offer by reusing existing relay connection")
			return
		}
		w.log.Errorf("failed to open connection via Relay: %s", err)
		return
	}

	w.relayLock.Lock()
	w.relayedConn = relayedConn
	w.relayLock.Unlock()

	err = w.relayManager.AddCloseListener(srv, w.onRelayClientDisconnected)
	if err != nil {
		log.Errorf("failed to add close listener: %s", err)
		_ = relayedConn.Close()
		return
	}

	w.log.Debugf("peer conn opened via Relay: %s", srv)
	w.onConnReady(RelayConnInfo{
		RelayedConn:     relayedConn,
		RosenpassPubKey: remoteOfferAnswer.RosenpassPubKey,
		RosenpassAddr:   remoteOfferAnswer.RosenpassAddr,
	})
}

func (w *WorkerRelay) RelayInstanceAddress() (string, netip.Addr, error) {
	return w.relayManager.RelayInstanceAddress()
}

func (w *WorkerRelay) IsRelayConnectionSupportedWithPeer() bool {
	return w.relaySupportedOnRemotePeer.Load() && w.RelayIsSupportedLocally()
}

func (w *WorkerRelay) RelayIsSupportedLocally() bool {
	return w.relayManager.HasRelayAddress()
}

func (w *WorkerRelay) CloseConn() {
	w.relayLock.Lock()
	defer w.relayLock.Unlock()
	if w.relayedConn == nil {
		return
	}

	if err := w.relayedConn.Close(); err != nil {
		w.log.Warnf("failed to close relay connection: %v", err)
	}
}

func (w *WorkerRelay) isRelaySupported(answer *signaling.OfferAnswer) bool {
	if !w.relayManager.HasRelayAddress() {
		return false
	}
	return answer.RelaySrvAddress != ""
}

func (w *WorkerRelay) preferredRelayServer(myRelayAddress, remoteRelayAddress string) string {
	if w.isController {
		return myRelayAddress
	}
	return remoteRelayAddress
}

func (w *WorkerRelay) onRelayClientDisconnected() {
	w.onDisconnected()
}
