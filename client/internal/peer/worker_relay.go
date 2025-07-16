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

type WorkerRelay struct {
	peerCtx      context.Context
	log          *log.Entry
	isController bool
	config       ConnConfig
	conn         *Conn
	relayManager relayClient.ManagerService

	relayedConn net.Conn
	relayLock   sync.Mutex

	relaySupportedOnRemotePeer atomic.Bool

	wgWatcher *WGWatcher
}

func NewWorkerRelay(ctx context.Context, log *log.Entry, ctrl bool, config ConnConfig, conn *Conn, relayManager relayClient.ManagerService, stateDump *stateDump) *WorkerRelay {
	r := &WorkerRelay{
		peerCtx:      ctx,
		log:          log,
		isController: ctrl,
		config:       config,
		conn:         conn,
		relayManager: relayManager,
		wgWatcher:    NewWGWatcher(log, config.WgConfig.WgInterface, config.Key, stateDump),
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

	relayedConn, err := w.relayManager.OpenConn(w.peerCtx, srv, w.config.Key)
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
	go w.conn.onRelayConnectionIsReady(RelayConnInfo{
		relayedConn:     relayedConn,
		rosenpassPubKey: remoteOfferAnswer.RosenpassPubKey,
		rosenpassAddr:   remoteOfferAnswer.RosenpassAddr,
	})
}

func (w *WorkerRelay) EnableWgWatcher(ctx context.Context) {
	w.wgWatcher.EnableWgWatcher(ctx, w.onWGDisconnected)
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

func (w *WorkerRelay) onWGDisconnected() {
	w.relayLock.Lock()
	_ = w.relayedConn.Close()
	w.relayLock.Unlock()

	w.conn.onRelayDisconnected()
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

func (w *WorkerRelay) onRelayClientDisconnected() {
	w.wgWatcher.DisableWgWatcher()
	go w.conn.onRelayDisconnected()
}
