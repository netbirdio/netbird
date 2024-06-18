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

type ConnectorRelay struct {
	ctx                context.Context
	log                *log.Entry
	relayManager       *relayClient.Manager
	config             ConnConfig
	onRelayConnReadyFN OnRelayReadyCallback
	doHandshakeFn      DoHandshake
}

func NewConnectorRelay(ctx context.Context, log *log.Entry, relayManager *relayClient.Manager, config ConnConfig, onRelayConnReadyFN OnRelayReadyCallback, doHandshakeFn DoHandshake) *ConnectorRelay {
	return &ConnectorRelay{
		ctx:                ctx,
		log:                log,
		relayManager:       relayManager,
		config:             config,
		onRelayConnReadyFN: onRelayConnReadyFN,
		doHandshakeFn:      doHandshakeFn,
	}
}

// SetupRelayConnection todo: this function is not completed. Make no sense to put it in a for loop because we are not waiting for any event
func (conn *ConnectorRelay) SetupRelayConnection() {
	for {
		if !conn.waitForReconnectTry() {
			return
		}

		remoteOfferAnswer, err := conn.doHandshakeFn()
		if err != nil {
			if errors.Is(err, ErrSignalIsNotReady) {
				conn.log.Infof("signal client isn't ready, skipping connection attempt")
			}
			conn.log.Errorf("failed to do handshake: %v", err)
			continue
		}

		if !conn.isRelaySupported(remoteOfferAnswer) {
			// todo should we retry?
			continue
		}

		// the relayManager will return with error in case if the connection has lost with relay server
		currentRelayAddress, err := conn.relayManager.RelayAddress()
		if err != nil {
			continue
		}

		srv := conn.preferredRelayServer(currentRelayAddress.String(), remoteOfferAnswer.RelaySrvAddress)
		relayedConn, err := conn.relayManager.OpenConn(srv, conn.config.Key)
		if err != nil {
			continue
		}

		go conn.onRelayConnReadyFN(RelayConnInfo{
			relayedConn:     relayedConn,
			rosenpassPubKey: remoteOfferAnswer.RosenpassPubKey,
			rosenpassAddr:   remoteOfferAnswer.RosenpassAddr,
		})

		// todo: waitForDisconnection()
	}
}

func (conn *ConnectorRelay) RelayAddress() (net.Addr, error) {
	return conn.relayManager.RelayAddress()
}

// todo check my side too
func (conn *ConnectorRelay) isRelaySupported(answer *OfferAnswer) bool {
	return answer.RelaySrvAddress != ""
}

func (conn *ConnectorRelay) preferredRelayServer(myRelayAddress, remoteRelayAddress string) string {
	if conn.config.LocalKey > conn.config.Key {
		return myRelayAddress
	}
	return remoteRelayAddress
}

func (conn *ConnectorRelay) RelayIsSupportedLocally() bool {
	return conn.relayManager.HasRelayAddress()
}

// waitForReconnectTry waits for a random duration before trying to reconnect
func (conn *ConnectorRelay) waitForReconnectTry() bool {
	minWait := 500
	maxWait := 2000
	duration := time.Duration(rand.Intn(maxWait-minWait)+minWait) * time.Millisecond
	select {
	case <-conn.ctx.Done():
		return false
	case <-time.After(duration):
		return true
	}
}
