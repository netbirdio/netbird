package peer

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"time"

	log "github.com/sirupsen/logrus"

	relayClient "github.com/netbirdio/netbird/relay/client"
)

type OnRelayReadyCallback func(info RelayConnInfo)

type RelayConnInfo struct {
	relayedConn     net.Conn
	rosenpassPubKey []byte
	rosenpassAddr   string
}

type WorkerRelay struct {
	ctx                context.Context
	log                *log.Entry
	relayManager       *relayClient.Manager
	config             ConnConfig
	onRelayConnReadyFN OnRelayReadyCallback
	doHandshakeFn      DoHandshake
}

func NewWorkerRelay(ctx context.Context, log *log.Entry, relayManager *relayClient.Manager, config ConnConfig, onRelayConnReadyFN OnRelayReadyCallback, doHandshakeFn DoHandshake) *WorkerRelay {
	return &WorkerRelay{
		ctx:                ctx,
		log:                log,
		relayManager:       relayManager,
		config:             config,
		onRelayConnReadyFN: onRelayConnReadyFN,
		doHandshakeFn:      doHandshakeFn,
	}
}

// SetupRelayConnection todo: this function is not completed. Make no sense to put it in a for loop because we are not waiting for any event
func (w *WorkerRelay) SetupRelayConnection() {
	for {
		if !w.waitForReconnectTry() {
			return
		}

		remoteOfferAnswer, err := w.doHandshakeFn()
		if err != nil {
			if errors.Is(err, ErrSignalIsNotReady) {
				w.log.Infof("signal client isn't ready, skipping connection attempt")
			}
			w.log.Errorf("failed to do handshake: %v", err)
			continue
		}

		if !w.isRelaySupported(remoteOfferAnswer) {
			// todo should we retry?
			continue
		}

		// the relayManager will return with error in case if the connection has lost with relay server
		currentRelayAddress, err := w.relayManager.RelayAddress()
		if err != nil {
			continue
		}

		srv := w.preferredRelayServer(currentRelayAddress.String(), remoteOfferAnswer.RelaySrvAddress)
		relayedConn, err := w.relayManager.OpenConn(srv, w.config.Key)
		if err != nil {
			continue
		}

		go w.onRelayConnReadyFN(RelayConnInfo{
			relayedConn:     relayedConn,
			rosenpassPubKey: remoteOfferAnswer.RosenpassPubKey,
			rosenpassAddr:   remoteOfferAnswer.RosenpassAddr,
		})

		// todo: waitForDisconnection()
	}
}

func (w *WorkerRelay) RelayAddress() (net.Addr, error) {
	return w.relayManager.RelayAddress()
}

// todo check my side too
func (w *WorkerRelay) isRelaySupported(answer *OfferAnswer) bool {
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

// waitForReconnectTry waits for a random duration before trying to reconnect
func (w *WorkerRelay) waitForReconnectTry() bool {
	minWait := 500
	maxWait := 2000
	duration := time.Duration(rand.Intn(maxWait-minWait)+minWait) * time.Millisecond

	timeout := time.NewTimer(duration)
	defer timeout.Stop()

	select {
	case <-w.ctx.Done():
		return false
	case <-timeout.C:
		return true
	}
}
