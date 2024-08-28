package peer

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	relayClient "github.com/netbirdio/netbird/relay/client"
)

var (
	wgHandshakePeriod   = 2 * time.Minute
	wgHandshakeOvertime = 30 * time.Second
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
	config       ConnConfig
	relayManager relayClient.ManagerService
	callBacks    WorkerRelayCallbacks

	relayedConn      net.Conn
	ctxWgWatch       context.Context
	ctxCancelWgWatch context.CancelFunc
	ctxLock          sync.Mutex

	relaySupportedOnRemotePeer atomic.Bool
}

func NewWorkerRelay(log *log.Entry, config ConnConfig, relayManager relayClient.ManagerService, callbacks WorkerRelayCallbacks) *WorkerRelay {
	r := &WorkerRelay{
		log:          log,
		config:       config,
		relayManager: relayManager,
		callBacks:    callbacks,
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
			w.log.Infof("do not need to reopen relay connection")
			return
		}
		w.log.Errorf("failed to open connection via Relay: %s", err)
		return
	}
	w.relayedConn = relayedConn

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
	w.log.Debugf("enable WireGuard watcher")
	w.ctxLock.Lock()
	defer w.ctxLock.Unlock()

	if w.ctxWgWatch != nil && w.ctxWgWatch.Err() == nil {
		return
	}

	ctx, ctxCancel := context.WithCancel(ctx)
	go w.wgStateCheck(ctx)
	w.ctxWgWatch = ctx
	w.ctxCancelWgWatch = ctxCancel

}

func (w *WorkerRelay) DisableWgWatcher() {
	w.ctxLock.Lock()
	defer w.ctxLock.Unlock()

	if w.ctxCancelWgWatch == nil {
		return
	}

	w.log.Debugf("disable WireGuard watcher")

	w.ctxCancelWgWatch()
}

func (w *WorkerRelay) RelayInstanceAddress() (string, error) {
	return w.relayManager.RelayInstanceAddress()
}

func (w *WorkerRelay) IsRelayConnectionSupportedWithPeer() bool {
	return w.relaySupportedOnRemotePeer.Load() && w.RelayIsSupportedLocally()
}

func (w *WorkerRelay) IsController() bool {
	return w.config.LocalKey > w.config.Key
}

func (w *WorkerRelay) RelayIsSupportedLocally() bool {
	return w.relayManager.HasRelayAddress()
}

// wgStateCheck help to check the state of the wireguard handshake and relay connection
func (w *WorkerRelay) wgStateCheck(ctx context.Context) {
	timer := time.NewTimer(wgHandshakeOvertime)
	defer timer.Stop()
	expected := wgHandshakeOvertime
	for {
		select {
		case <-timer.C:
			lastHandshake, err := w.wgState()
			if err != nil {
				w.log.Errorf("failed to read wg stats: %v", err)
				continue
			}
			w.log.Tracef("last handshake: %v", lastHandshake)

			if time.Since(lastHandshake) > expected {
				w.log.Infof("Wireguard handshake timed out, closing relay connection")
				_ = w.relayedConn.Close()
				w.callBacks.OnDisconnected()
				return
			}
			resetTime := time.Until(lastHandshake.Add(wgHandshakePeriod + wgHandshakeOvertime))
			timer.Reset(resetTime)
			expected = wgHandshakePeriod
		case <-ctx.Done():
			w.log.Debugf("WireGuard watcher stopped")
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

func (w *WorkerRelay) onRelayMGDisconnected() {
	w.ctxLock.Lock()
	defer w.ctxLock.Unlock()

	if w.ctxCancelWgWatch != nil {
		w.ctxCancelWgWatch()
	}
	w.callBacks.OnDisconnected()
}
