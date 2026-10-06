package peer

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	defaultWgKeepAlive = 25 * time.Second
	fallbackDelay      = 5 * time.Second
)

type EndpointUpdater struct {
	log       *logrus.Entry
	wgConfig  WgConfig
	initiator bool

	// mu protects cancelFunc
	mu         sync.Mutex
	cancelFunc func()
	updateWg   sync.WaitGroup
}

func NewEndpointUpdater(log *logrus.Entry, wgConfig WgConfig, initiator bool) *EndpointUpdater {
	return &EndpointUpdater{
		log:       log,
		wgConfig:  wgConfig,
		initiator: initiator,
	}
}

func (e *EndpointUpdater) ConfigureWGEndpoint(addr *net.UDPAddr, presharedKey *wgtypes.Key) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.initiator {
		e.log.Debugf("configure up WireGuard as initiator")
		return e.configureAsInitiator(addr, presharedKey)
	}

	e.log.Debugf("configure up WireGuard as responder")
	return e.configureAsResponder(addr, presharedKey)
}

func (e *EndpointUpdater) SwitchWGEndpoint(addr *net.UDPAddr, presharedKey *wgtypes.Key) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// prevent to run new update while cancel the previous update
	e.waitForCloseTheDelayedUpdate()

	return e.updateWireGuardPeer(addr, presharedKey)
}

func (e *EndpointUpdater) RemoveWgPeer() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.waitForCloseTheDelayedUpdate()
	return e.wgConfig.WgInterface.RemovePeer(e.wgConfig.RemoteKey)
}

func (e *EndpointUpdater) RemoveEndpointAddress() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.waitForCloseTheDelayedUpdate()
	return e.wgConfig.WgInterface.RemoveEndpointAddress(e.wgConfig.RemoteKey)
}

func (e *EndpointUpdater) configureAsInitiator(addr *net.UDPAddr, presharedKey *wgtypes.Key) error {
	if err := e.updateWireGuardPeer(addr, presharedKey); err != nil {
		return err
	}
	return nil
}

func (e *EndpointUpdater) configureAsResponder(addr *net.UDPAddr, presharedKey *wgtypes.Key) error {
	// prevent to run new update while cancel the previous update
	e.waitForCloseTheDelayedUpdate()

	e.log.Debugf("configure up WireGuard and wait for handshake")
	var ctx context.Context
	ctx, e.cancelFunc = context.WithCancel(context.Background())
	e.updateWg.Add(1)
	go e.scheduleDelayedUpdate(ctx, addr)

	if err := e.updateWireGuardPeer(nil, presharedKey); err != nil {
		e.waitForCloseTheDelayedUpdate()
		return err
	}
	return nil
}

func (e *EndpointUpdater) waitForCloseTheDelayedUpdate() {
	if e.cancelFunc == nil {
		return
	}

	e.cancelFunc()
	e.cancelFunc = nil
	e.updateWg.Wait()
}

// scheduleDelayedUpdate waits for the fallback period, then sets the responder's real
// endpoint. It deliberately passes a nil preshared key so it only updates the endpoint
// and leaves the current PSK untouched: the PSK captured when this was scheduled may be
// stale by now (e.g. the post-quantum bootstrap derived a fresher PSK within the
// fallback window, applied via SetPresharedKey), and re-applying the captured one would
// revert WireGuard to a key the remote peer no longer uses — a mismatch that stalls the
// handshake until the next retry.
func (e *EndpointUpdater) scheduleDelayedUpdate(ctx context.Context, addr *net.UDPAddr) {
	defer e.updateWg.Done()
	t := time.NewTimer(fallbackDelay)
	defer t.Stop()

	select {
	case <-ctx.Done():
		return
	case <-t.C:
		if err := e.updateWireGuardPeer(addr, nil); err != nil {
			e.log.Errorf("failed to update WireGuard peer, address: %s, error: %v", addr, err)
		}
	}
}

func (e *EndpointUpdater) updateWireGuardPeer(endpoint *net.UDPAddr, presharedKey *wgtypes.Key) error {
	return e.wgConfig.WgInterface.UpdatePeer(
		e.wgConfig.RemoteKey,
		e.wgConfig.AllowedIps,
		defaultWgKeepAlive,
		endpoint,
		presharedKey,
	)
}

// wgConfigWorkaround is a workaround for the issue with WireGuard configuration update
// When update a peer configuration in near to each other time, the second update can be ignored by WireGuard
func wgConfigWorkaround() {
	time.Sleep(100 * time.Millisecond)
}
