package peer

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"

	log "github.com/sirupsen/logrus"

	relayClient "github.com/netbirdio/netbird/relay/client"
)

type RelayConnInfo struct {
	relayedConn     net.Conn
	rosenpassPubKey []byte
	rosenpassAddr   string
}

type WorkerRelayCallbacks struct {
	OnConnReady    func(RelayConnInfo)
	OnDisconnected func()
}

type WorkerRelay struct {
	log          *log.Entry
	isController bool
	config       ConnConfig
	relayManager relayClient.ManagerService
	callBacks    WorkerRelayCallbacks

	relayedConn net.Conn
	relayLock   sync.Mutex

	relaySupportedOnRemotePeer atomic.Bool

	wgWatcher *WGWatcher
}

func NewWorkerRelay(log *log.Entry, ctrl bool, config ConnConfig, relayManager relayClient.ManagerService, callbacks WorkerRelayCallbacks) *WorkerRelay {
	r := &WorkerRelay{
		log:          log,
		isController: ctrl,
		config:       config,
		relayManager: relayManager,
		callBacks:    callbacks,
		wgWatcher:    NewWGWatcher(log, config.WgConfig.WgInterface, config.Key),
	}
	return r
}

func (w *WorkerRelay) OnNewOffer(remoteOfferAnswer *OfferAnswer) {
	if !w.isRelaySupported(remoteOfferAnswer) {
		w.log.Infof("Relay is not supported by remote peer")
		w.relaySupportedOnRemotePeer.Store(false)
		return
	}
	w.relaySupportedOnRemotePeer.Store(true)

	// the relayManager will return with error in case if the connection has lost with relay server
	currentRelayAddress, err := w.relayManager.RelayInstanceAddress()
	if err != nil {
		w.log.Errorf("failed to handle new offer: %s", err)
		return
	}

	srv := w.preferredRelayServer(currentRelayAddress, remoteOfferAnswer.RelaySrvAddress)

	relayedConn, err := w.relayManager.OpenConn(srv, w.config.Key)
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

	err = w.relayManager.AddCloseListener(srv, w.onRelayMGDisconnected)
	if err != nil {
		log.Errorf("failed to add close listener: %s", err)
		_ = relayedConn.Close()
		return
	}

	w.log.Debugf("peer conn opened via Relay: %s", srv)
	go w.callBacks.OnConnReady(RelayConnInfo{
		relayedConn:     relayedConn,
		rosenpassPubKey: remoteOfferAnswer.RosenpassPubKey,
		rosenpassAddr:   remoteOfferAnswer.RosenpassAddr,
	})
}

func (w *WorkerRelay) EnableWgWatcher(ctx context.Context) {
	w.wgWatcher.EnableWgWatcher(ctx, w.disconnected)
}

func (w *WorkerRelay) DisableWgWatcher() {
	w.wgWatcher.DisableWgWatcher()
}

func (w *WorkerRelay) RelayInstanceAddress() (string, error) {
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

func (w *WorkerRelay) disconnected() {
	w.relayLock.Lock()
	_ = w.relayedConn.Close()
	w.relayLock.Unlock()

	w.callBacks.OnDisconnected()
}

func (w *WorkerRelay) isRelaySupported(answer *OfferAnswer) bool {
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

func (w *WorkerRelay) onRelayMGDisconnected() {
	w.wgWatcher.DisableWgWatcher()
	go w.callBacks.OnDisconnected()
}
