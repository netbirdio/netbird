package peer

import (
	"context"
	"errors"
	"net"
	"time"

	log "github.com/sirupsen/logrus"

	relayClient "github.com/netbirdio/netbird/relay/client"
)

var (
	wgHandshakePeriod   = 2 * time.Minute
	wgHandshakeOvertime = 30000 * time.Millisecond
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
	parentCtx    context.Context
	log          *log.Entry
	config       ConnConfig
	relayManager relayClient.ManagerService
	conn         WorkerRelayCallbacks

	ctxCancel context.CancelFunc
}

func NewWorkerRelay(ctx context.Context, log *log.Entry, config ConnConfig, relayManager relayClient.ManagerService, callbacks WorkerRelayCallbacks) *WorkerRelay {
	r := &WorkerRelay{
		parentCtx:    ctx,
		log:          log,
		config:       config,
		relayManager: relayManager,
		conn:         callbacks,
	}
	return r
}

func (w *WorkerRelay) OnNewOffer(remoteOfferAnswer *OfferAnswer) {
	if !w.isRelaySupported(remoteOfferAnswer) {
		w.log.Infof("Relay is not supported by remote peer")
		return
	}

	// the relayManager will return with error in case if the connection has lost with relay server
	currentRelayAddress, err := w.relayManager.RelayInstanceAddress()
	if err != nil {
		w.log.Errorf("failed to handle new offer: %s", err)
		return
	}

	srv := w.preferredRelayServer(currentRelayAddress, remoteOfferAnswer.RelaySrvAddress)

	relayedConn, err := w.relayManager.OpenConn(srv, w.config.Key)
	if err != nil {
		// todo handle all type errors
		if errors.Is(err, relayClient.ErrConnAlreadyExists) {
			w.log.Infof("do not need to reopen relay connection")
			return
		}
		w.log.Errorf("failed to open connection via Relay: %s", err)
		return
	}

	ctx, ctxCancel := context.WithCancel(w.parentCtx)
	w.ctxCancel = ctxCancel

	err = w.relayManager.AddCloseListener(srv, w.disconnected)
	if err != nil {
		log.Errorf("failed to add close listener: %s", err)
		_ = relayedConn.Close()
		ctxCancel()
		return
	}

	go w.wgStateCheck(ctx, relayedConn)

	w.log.Debugf("peer conn opened via Relay: %s", srv)
	go w.conn.OnConnReady(RelayConnInfo{
		relayedConn:     relayedConn,
		rosenpassPubKey: remoteOfferAnswer.RosenpassPubKey,
		rosenpassAddr:   remoteOfferAnswer.RosenpassAddr,
	})
}

func (w *WorkerRelay) RelayInstanceAddress() (string, error) {
	return w.relayManager.RelayInstanceAddress()
}

func (w *WorkerRelay) IsController() bool {
	return w.config.LocalKey > w.config.Key
}

func (w *WorkerRelay) RelayIsSupportedLocally() bool {
	return w.relayManager.HasRelayAddress()
}

// wgStateCheck help to check the state of the wireguard handshake and relay connection
func (w *WorkerRelay) wgStateCheck(ctx context.Context, conn net.Conn) {
	timer := time.NewTimer(wgHandshakeOvertime)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			lastHandshake, err := w.wgState()
			if err != nil {
				w.log.Errorf("failed to read wg stats: %v", err)
				continue
			}
			w.log.Tracef("last handshake: %v", lastHandshake)

			if time.Since(lastHandshake) > wgHandshakePeriod {
				w.log.Infof("Wireguard handshake timed out, closing relay connection")
				_ = conn.Close()
				w.conn.OnDisconnected()
				return
			}
			resetTime := time.Until(lastHandshake.Add(wgHandshakeOvertime + wgHandshakePeriod))
			timer.Reset(resetTime)
		case <-ctx.Done():
			return
		}
	}
}

func (w *WorkerRelay) isRelaySupported(answer *OfferAnswer) bool {
	if !w.relayManager.HasRelayAddress() {
		return false
	}
	return answer.RelaySrvAddress != ""
}

func (w *WorkerRelay) preferredRelayServer(myRelayAddress, remoteRelayAddress string) string {
	if w.IsController() {
		return myRelayAddress
	}
	return remoteRelayAddress
}

func (w *WorkerRelay) wgState() (time.Time, error) {
	wgState, err := w.config.WgConfig.WgInterface.GetStats(w.config.Key)
	if err != nil {
		return time.Time{}, err
	}
	return wgState.LastHandshake, nil
}

func (w *WorkerRelay) disconnected() {
	if w.ctxCancel != nil {
		w.ctxCancel()
	}
	w.conn.OnDisconnected()
}
