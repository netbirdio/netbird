package peer

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"

	log "github.com/sirupsen/logrus"

	relayClient "github.com/netbirdio/netbird/shared/relay/client"
)

type RelayConnInfo struct {
	relayedConn     *relayClient.Conn
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

	relayedConn *relayClient.Conn
	relayLock   sync.Mutex

	relaySupportedOnRemotePeer atomic.Bool

	// remoteSessionID is the session ID of the remote's latest relay-only offer.
	// Only OnNewOffer touches it, and the offer listener serializes those calls.
	remoteSessionID ICESessionID
}

func NewWorkerRelay(ctx context.Context, log *log.Entry, ctrl bool, config ConnConfig, conn *Conn, relayManager *relayClient.Manager) *WorkerRelay {
	r := &WorkerRelay{
		peerCtx:      ctx,
		log:          log,
		isController: ctrl,
		config:       config,
		conn:         conn,
		relayManager: relayManager,
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

	if w.remoteRestarted(remoteOfferAnswer) {
		w.log.Infof("remote peer started a new session, dropping the relayed connection of its previous one")
		w.dropRelayedConn()
	}

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

	relayedConn, err := w.relayManager.OpenConn(w.peerCtx, srv, w.config.Key, serverIP)
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

	go w.watchRelayedConn(relayedConn)

	w.log.Debugf("peer conn opened via Relay: %s", srv)
	go w.conn.onRelayConnectionIsReady(RelayConnInfo{
		relayedConn:     relayedConn,
		rosenpassPubKey: remoteOfferAnswer.RosenpassPubKey,
		rosenpassAddr:   remoteOfferAnswer.RosenpassAddr,
	})
}

// remoteRestarted records the session ID of a relay-only offer and reports
// whether it differs from the previous one, which means the remote peer created
// a new connection. Offers with ICE credentials carry the ICE agent's session,
// which rotates independently of a restart, and offers from peers that send no
// session ID are ignored.
func (w *WorkerRelay) remoteRestarted(remoteOfferAnswer *OfferAnswer) bool {
	if remoteOfferAnswer.hasICECredentials() || remoteOfferAnswer.SessionID == nil {
		return false
	}

	prev := w.remoteSessionID
	w.remoteSessionID = *remoteOfferAnswer.SessionID
	return prev != "" && prev != w.remoteSessionID
}

// dropRelayedConn tears down the relayed connection kept for the remote's
// previous session. The teardown runs before the connection is closed so the
// overlay session of the previous instance is flushed before a replacement is
// configured; the close notification that follows is ignored as superseded.
func (w *WorkerRelay) dropRelayedConn() {
	w.relayLock.Lock()
	relayedConn := w.relayedConn
	w.relayedConn = nil
	w.relayLock.Unlock()

	if relayedConn == nil {
		return
	}

	w.conn.onRelayDisconnected(relayedConn)
	if err := relayedConn.Close(); err != nil {
		w.log.Debugf("failed to close relayed connection of the previous remote session: %v", err)
	}
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

func (w *WorkerRelay) IsTransportConnected() bool {
	return w.relayManager.Ready()
}

func (w *WorkerRelay) CloseConn() {
	w.relayLock.Lock()
	conn := w.relayedConn
	w.relayedConn = nil
	w.relayLock.Unlock()

	if conn == nil {
		return
	}

	if err := conn.Close(); err != nil {
		w.log.Warnf("failed to close relay connection: %v", err)
	}
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

func (w *WorkerRelay) watchRelayedConn(relayedConn *relayClient.Conn) {
	<-relayedConn.Context().Done()

	w.conn.onRelayDisconnected(relayedConn)
}
