package peer

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	defaultWgKeepAlive = 25 * time.Second
	fallbackDelay      = 5 * time.Second
)

// wgPath names the transport a WireGuard endpoint points at.
type wgPath string

const (
	wgPathICE   wgPath = "ice"
	wgPathRelay wgPath = "relay"
)

type EndpointUpdater struct {
	log       *logrus.Entry
	wgConfig  WgConfig
	initiator bool

	// keepAlive and path are read by the delayed update goroutine without mu.
	keepAlive atomic.Int64
	path      atomic.Value

	// mu protects cancelFunc
	mu         sync.Mutex
	cancelFunc func()
	updateWg   sync.WaitGroup
}

func NewEndpointUpdater(log *logrus.Entry, wgConfig WgConfig, initiator bool) *EndpointUpdater {
	e := &EndpointUpdater{
		log:       log,
		wgConfig:  wgConfig,
		initiator: initiator,
	}
	e.keepAlive.Store(int64(defaultWgKeepAlive))
	return e
}

func (e *EndpointUpdater) ConfigureWGEndpoint(addr *net.UDPAddr, presharedKey *wgtypes.Key, path wgPath) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.setPath(path)

	if e.initiator {
		e.log.Debugf("configure up WireGuard as initiator")
		return e.configureAsInitiator(addr, presharedKey)
	}

	e.log.Debugf("configure up WireGuard as responder")
	return e.configureAsResponder(addr, presharedKey)
}

func (e *EndpointUpdater) SwitchWGEndpoint(addr *net.UDPAddr, presharedKey *wgtypes.Key, path wgPath) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// prevent to run new update while cancel the previous update
	e.waitForCloseTheDelayedUpdate()

	e.setPath(path)
	return e.updateWireGuardPeer(addr, presharedKey)
}

// DisableRelayKeepalive sets the persistent keepalive of a relayed peer to 0. It
// leaves the endpoint, allowed IPs and preshared key as they are. It does nothing
// when the current path is not relay. The next configure or switch restores the
// default keepalive.
func (e *EndpointUpdater) DisableRelayKeepalive() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.currentPath() != wgPathRelay || e.keepAlive.Load() == 0 {
		return nil
	}
	e.keepAlive.Store(0)
	e.logKeepalive()
	return e.wgConfig.WgInterface.UpdatePeer(e.wgConfig.RemoteKey, nil, 0, nil, nil)
}

func (e *EndpointUpdater) setPath(path wgPath) {
	e.path.Store(path)
	e.keepAlive.Store(int64(defaultWgKeepAlive))
}

func (e *EndpointUpdater) currentPath() wgPath {
	path, _ := e.path.Load().(wgPath)
	return path
}

func (e *EndpointUpdater) logKeepalive() {
	key := e.wgConfig.RemoteKey
	if len(key) > 8 {
		key = key[:8]
	}
	e.log.Infof("wgka: peer=%s path=%s keepalive=%d", key, e.currentPath(), time.Duration(e.keepAlive.Load())/time.Second)
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
	e.logKeepalive()
	return e.wgConfig.WgInterface.UpdatePeer(
		e.wgConfig.RemoteKey,
		e.wgConfig.AllowedIps,
		time.Duration(e.keepAlive.Load()),
		endpoint,
		presharedKey,
	)
}

// wgConfigWorkaround is a workaround for the issue with WireGuard configuration update
// When update a peer configuration in near to each other time, the second update can be ignored by WireGuard
func wgConfigWorkaround() {
	time.Sleep(100 * time.Millisecond)
}
