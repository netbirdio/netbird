package peer

import (
	"context"
	"errors"
	"net"
	"net/netip"
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

	// relayConnStale is set to true when an event indicates that the current
	// relay connection entry in the relay client's conns map is no longer
	// backed by a live peer session (e.g. local WG handshake timeout, relay
	// server close event, explicit CloseConn). When OnNewOffer observes
	// ErrConnAlreadyExists, it only closes the stale entry if this flag is
	// set; otherwise it bails out and reuses the existing healthy connection.
	relayConnStale atomic.Bool
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
			// Only tear down the existing conn if something previously marked
			// it as stale (local WG handshake timeout, relay server close, or
			// explicit CloseConn). Without that signal, the existing conn is
			// assumed healthy and is reused — unconditional close on every
			// colliding offer causes an infinite tear-down/rebuild loop when
			// the remote peer sends rapid successive offers.
			if !w.relayConnStale.Load() {
				w.log.Debugf("relay conn already exists and is not marked stale, reusing")
				return
			}
			w.log.Infof("relay conn already exists and is marked stale, closing and retrying")
			w.relayManager.CloseConnByPeerKey(srv, w.config.Key)
			relayedConn, err = w.relayManager.OpenConn(w.peerCtx, srv, w.config.Key)
			if err != nil {
				w.log.Errorf("failed to reopen connection via Relay after closing stale: %s", err)
				return
			}
			w.relayConnStale.Store(false)
		} else {
			w.log.Errorf("failed to open connection via Relay: %s", err)
			return
		}
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

	w.relayConnStale.Store(true)
	if err := w.relayedConn.Close(); err != nil {
		w.log.Warnf("failed to close relay connection: %v", err)
	}
}

// MarkStale marks the relay connection entry as stale so that the next
// OnNewOffer call with ErrConnAlreadyExists will tear it down and open a
// fresh one. Callers signal staleness from outside the relay client path,
// e.g. when the local WG handshake watcher fires while the relay is the
// active transport.
func (w *WorkerRelay) MarkStale() {
	w.relayConnStale.Store(true)
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
	w.relayConnStale.Store(true)
	go w.conn.onRelayDisconnected()
}
