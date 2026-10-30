package peer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"

	log "github.com/sirupsen/logrus"

	relayClient "github.com/netbirdio/netbird/shared/relay/client"
)

// maxSupersededSessionIDs bounds how many replaced remote session IDs are kept to
// recognize late offers of earlier sessions.
const maxSupersededSessionIDs = 4

// remoteSessionState classifies a remote offer against the sessions seen before.
type remoteSessionState int

const (
	remoteSessionCurrent remoteSessionState = iota
	remoteSessionSuperseded
	remoteSessionRestarted
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

	// remoteSessionID is the session ID of the remote's latest relay-only offer, and
	// supersededSessionIDs the most recent ones it replaced. Only OnNewOffer touches
	// them, and the offer listener serializes those calls.
	remoteSessionID      ICESessionID
	supersededSessionIDs []ICESessionID
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

	switch w.trackRemoteSession(remoteOfferAnswer) {
	case remoteSessionSuperseded:
		w.log.Debugf("ignoring a late offer of a superseded remote session")
		return
	case remoteSessionRestarted:
		w.log.Debugf("dropping the relayed connection of the remote's previous session")
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

// trackRemoteSession records the session of a remote offer and classifies it. Relay-only
// offers carry an ID that is fixed for the remote's connection, so a new ID means the
// remote created a new connection, and an ID that was already replaced belongs to a
// late offer. A peer only sends relay-only offers once it learned that this side has
// no ICE, and only a new connection starts with ICE offers again, so an offer with ICE
// credentials after relay-only ones also means a new connection. The ICE session ID
// itself rotates with the ICE agent and is not tracked. Offers from peers that send
// no session ID are never classified as a restart.
func (w *WorkerRelay) trackRemoteSession(remoteOfferAnswer *OfferAnswer) remoteSessionState {
	if remoteOfferAnswer.hasICECredentials() {
		if w.remoteSessionID == "" {
			return remoteSessionCurrent
		}
		w.log.Infof("remote peer started a new session: ICE offer after relay-only offers of session %s", w.remoteSessionID)
		w.supersedeRemoteSession("")
		return remoteSessionRestarted
	}
	if remoteOfferAnswer.SessionID == nil {
		return remoteSessionCurrent
	}

	sid := *remoteOfferAnswer.SessionID
	switch {
	case slices.Contains(w.supersededSessionIDs, sid):
		return remoteSessionSuperseded
	case sid == w.remoteSessionID:
		return remoteSessionCurrent
	case w.remoteSessionID == "":
		w.remoteSessionID = sid
		return remoteSessionCurrent
	default:
		w.log.Infof("remote peer started a new session: relay-only session %s replaced %s", sid, w.remoteSessionID)
		w.supersedeRemoteSession(sid)
		return remoteSessionRestarted
	}
}

// supersedeRemoteSession replaces the tracked remote session with next and keeps the
// replaced ID to recognize late offers of it.
func (w *WorkerRelay) supersedeRemoteSession(next ICESessionID) {
	w.supersededSessionIDs = append(w.supersededSessionIDs, w.remoteSessionID)
	if len(w.supersededSessionIDs) > maxSupersededSessionIDs {
		w.supersededSessionIDs = w.supersededSessionIDs[1:]
	}
	w.remoteSessionID = next
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
	// The teardown closes the connection through its proxy when it was in use.
	if err := relayedConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
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
