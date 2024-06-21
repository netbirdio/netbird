package peer

import (
	"context"
	"net"

	log "github.com/sirupsen/logrus"

	relayClient "github.com/netbirdio/netbird/relay/client"
)

type RelayConnInfo struct {
	relayedConn     net.Conn
	rosenpassPubKey []byte
	rosenpassAddr   string
}

type WorkerRelayCallbacks struct {
	OnConnReady     func(RelayConnInfo)
	OnStatusChanged func(ConnStatus)
}

type WorkerRelay struct {
	ctx          context.Context
	log          *log.Entry
	config       ConnConfig
	relayManager *relayClient.Manager
	conn         WorkerRelayCallbacks
}

func NewWorkerRelay(ctx context.Context, log *log.Entry, config ConnConfig, relayManager *relayClient.Manager, callbacks WorkerRelayCallbacks) *WorkerRelay {
	return &WorkerRelay{
		ctx:          ctx,
		log:          log,
		config:       config,
		relayManager: relayManager,
		conn:         callbacks,
	}
}

func (w *WorkerRelay) OnNewOffer(remoteOfferAnswer *OfferAnswer) {
	if !w.isRelaySupported(remoteOfferAnswer) {
		w.log.Infof("Relay is not supported by remote peer")
		// todo should we retry?
		// if the remote peer doesn't support relay make no sense to retry infinity
		// but if the remote peer supports relay just the connection is lost we should retry
		return
	}

	// the relayManager will return with error in case if the connection has lost with relay server
	currentRelayAddress, err := w.relayManager.RelayAddress()
	if err != nil {
		w.log.Infof("local Relay connection is lost, skipping connection attempt")
		return
	}

	srv := w.preferredRelayServer(currentRelayAddress.String(), remoteOfferAnswer.RelaySrvAddress)
	relayedConn, err := w.relayManager.OpenConn(srv, w.config.Key)
	if err != nil {
		w.log.Infof("do not need to reopen relay connection: %s", err)
		return
	}

	go w.conn.OnConnReady(RelayConnInfo{
		relayedConn:     relayedConn,
		rosenpassPubKey: remoteOfferAnswer.RosenpassPubKey,
		rosenpassAddr:   remoteOfferAnswer.RosenpassAddr,
	})
}

func (w *WorkerRelay) RelayAddress() (net.Addr, error) {
	return w.relayManager.RelayAddress()
}

func (w *WorkerRelay) isRelaySupported(answer *OfferAnswer) bool {
	if !w.relayManager.HasRelayAddress() {
		return false
	}
	return answer.RelaySrvAddress != ""
}

func (w *WorkerRelay) preferredRelayServer(myRelayAddress, remoteRelayAddress string) string {
	if w.config.LocalKey > w.config.Key {
		return myRelayAddress
	}
	return remoteRelayAddress
}

func (w *WorkerRelay) RelayIsSupportedLocally() bool {
	return w.relayManager.HasRelayAddress()
}
