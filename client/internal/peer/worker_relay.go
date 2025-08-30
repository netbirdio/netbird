package peer

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	log "github.com/sirupsen/logrus"

	relayClient "github.com/netbirdio/netbird/shared/relay/client"
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
	relayManager *relayClient.Manager

	relayedConn net.Conn
	relayLock   sync.Mutex

	relaySupportedOnRemotePeer atomic.Bool

	wgWatcher *WGWatcher
}

func NewWorkerRelay(ctx context.Context, log *log.Entry, ctrl bool, config ConnConfig, conn *Conn, relayManager *relayClient.Manager, stateDump *stateDump) *WorkerRelay {
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

	// Check if we already have an active relay connection
	w.relayLock.Lock()
	existingConn := w.relayedConn
	w.relayLock.Unlock()
	
	if existingConn != nil {
		w.log.Debugf("relay connection already exists for peer %s, reusing it", w.config.Key)
		// Connection exists, just ensure proxy is set up if needed
		go w.conn.onRelayConnectionIsReady(RelayConnInfo{
			relayedConn:     existingConn,
			rosenpassPubKey: remoteOfferAnswer.RosenpassPubKey,
			rosenpassAddr:   remoteOfferAnswer.RosenpassAddr,
		})
		return
	}

	// the relayManager will return with error in case if the connection has lost with relay server
	currentRelayAddress, err := w.relayManager.RelayInstanceAddress()
	if err != nil {
		w.log.Errorf("failed to handle new offer: %s", err)
		return
	}

	srv := w.preferredRelayServer(currentRelayAddress, remoteOfferAnswer.RelaySrvAddress)

	relayedConn, err := w.relayManager.OpenConn(w.peerCtx, srv, w.config.Key)
	if err != nil {
		// The relay manager never actually returns ErrConnAlreadyExists - it returns
		// the existing connection with nil error. This error handling is for other failures.
		w.log.Errorf("failed to open connection via Relay: %s", err)
		return
	}

	w.relayLock.Lock()
	// Check if we already stored this connection (might happen if OpenConn returned existing)
	if w.relayedConn != nil && w.relayedConn == relayedConn {
		w.relayLock.Unlock()
		w.log.Debugf("OpenConn returned the same connection we already have for peer %s", w.config.Key)
		go w.conn.onRelayConnectionIsReady(RelayConnInfo{
			relayedConn:     relayedConn,
			rosenpassPubKey: remoteOfferAnswer.RosenpassPubKey,
			rosenpassAddr:   remoteOfferAnswer.RosenpassAddr,
		})
		return
	}
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
	// Clear the stored connection to allow reopening
	w.relayedConn = nil
}

func (w *WorkerRelay) onWGDisconnected() {
	w.relayLock.Lock()
	if w.relayedConn != nil {
		_ = w.relayedConn.Close()
		w.relayedConn = nil
	}
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
	// Clear the stored connection when relay disconnects
	w.relayLock.Lock()
	w.relayedConn = nil
	w.relayLock.Unlock()
	
	w.wgWatcher.DisableWgWatcher()
	go w.conn.onRelayDisconnected()
}
