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

	// mu protects cancelFunc and lastEndpoint
	mu         sync.Mutex
	cancelFunc func()
	updateWg   sync.WaitGroup
	// lastEndpoint is the most recent non-nil endpoint applied to the peer, used to
	// re-add it on a forced re-handshake (ForceRehandshake).
	lastEndpoint *net.UDPAddr
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

	if addr != nil {
		e.lastEndpoint = addr
	}

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

	if addr != nil {
		e.lastEndpoint = addr
	}

	// prevent to run new update while cancel the previous update
	e.waitForCloseTheDelayedUpdate()

	return e.updateWireGuardPeer(addr, presharedKey)
}

// ForceRehandshake removes and re-adds the peer so WireGuard drops the current session
// and negotiates a fresh one with the given PSK. Used when a post-quantum PSK is
// bootstrapped after the session already came up on a pre-PQ key. No-op if no endpoint
// has been applied yet (the pending config will pull the PSK itself).
func (e *EndpointUpdater) ForceRehandshake(presharedKey *wgtypes.Key) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.lastEndpoint == nil {
		return nil
	}
	// Cancel any pending delayed responder update: it carries the stale pre-PQ key and
	// would otherwise re-poison the session after we reset it.
	e.waitForCloseTheDelayedUpdate()
	if err := e.wgConfig.WgInterface.RemovePeer(e.wgConfig.RemoteKey); err != nil {
		return err
	}
	return e.updateWireGuardPeer(e.lastEndpoint, presharedKey)
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
	go e.scheduleDelayedUpdate(ctx, addr, presharedKey)

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

// scheduleDelayedUpdate waits for the fallback period before updating the endpoint
func (e *EndpointUpdater) scheduleDelayedUpdate(ctx context.Context, addr *net.UDPAddr, presharedKey *wgtypes.Key) {
	defer e.updateWg.Done()
	t := time.NewTimer(fallbackDelay)
	defer t.Stop()

	select {
	case <-ctx.Done():
		return
	case <-t.C:
		if err := e.updateWireGuardPeer(addr, presharedKey); err != nil {
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
