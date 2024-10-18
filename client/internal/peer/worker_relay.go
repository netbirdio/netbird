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
	wgHandshakePeriod   = 3 * time.Minute
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
	isController bool
	config       ConnConfig
	relayManager relayClient.ManagerService
	callBacks    WorkerRelayCallbacks

	relayedConn      net.Conn
	relayLock        sync.Mutex
	ctxWgWatch       context.Context
	ctxCancelWgWatch context.CancelFunc
	ctxLock          sync.Mutex

	relaySupportedOnRemotePeer atomic.Bool
}

func NewWorkerRelay(log *log.Entry, ctrl bool, config ConnConfig, relayManager relayClient.ManagerService, callbacks WorkerRelayCallbacks) *WorkerRelay {
	r := &WorkerRelay{
		log:          log,
		isController: ctrl,
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
			w.log.Debugf("handled offer by reusing existing relay connection")
			return
		}
		w.log.Errorf("failed to open connection via Relay: %s", err)
		return
	}

	w.relayLock.Lock()
	w.relayedConn = relayedConn
	w.relayLock.Unlock()

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
	w.ctxWgWatch = ctx
	w.ctxCancelWgWatch = ctxCancel

	w.wgStateCheck(ctx, ctxCancel)
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

func (w *WorkerRelay) RelayIsSupportedLocally() bool {
	return w.relayManager.HasRelayAddress()
}

func (w *WorkerRelay) CloseConn() {
	w.relayLock.Lock()
	defer w.relayLock.Unlock()
	if w.relayedConn == nil {
		return
	}

	err := w.relayedConn.Close()
	if err != nil {
		w.log.Warnf("failed to close relay connection: %v", err)
	}
}

// wgStateCheck help to check the state of the WireGuard handshake and relay connection
func (w *WorkerRelay) wgStateCheck(ctx context.Context, ctxCancel context.CancelFunc) {
	w.log.Debugf("WireGuard watcher started")
	lastHandshake, err := w.wgState()
	if err != nil {
		w.log.Warnf("failed to read wg stats: %v", err)
		lastHandshake = time.Time{}
	}

	go func(lastHandshake time.Time) {
		timer := time.NewTimer(wgHandshakeOvertime)
		defer timer.Stop()
		defer ctxCancel()

		for {
			select {
			case <-timer.C:
				handshake, err := w.wgState()
				if err != nil {
					w.log.Errorf("failed to read wg stats: %v", err)
					timer.Reset(wgHandshakeOvertime)
					continue
				}

				w.log.Tracef("previous handshake, handshake: %v, %v", lastHandshake, handshake)

				if handshake.Equal(lastHandshake) {
					w.log.Infof("WireGuard handshake timed out, closing relay connection: %v", handshake)
					w.relayLock.Lock()
					_ = w.relayedConn.Close()
					w.relayLock.Unlock()
					w.callBacks.OnDisconnected()
					return
				}

				resetTime := time.Until(handshake.Add(wgHandshakePeriod + wgHandshakeOvertime))
				lastHandshake = handshake
				timer.Reset(resetTime)
			case <-ctx.Done():
				w.log.Debugf("WireGuard watcher stopped")
				return
			}
		}
	}(lastHandshake)

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
	go w.callBacks.OnDisconnected()
}
