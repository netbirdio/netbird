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

	cancelFunc        func()
	configUpdateMutex sync.Mutex
}

func NewEndpointUpdater(log *logrus.Entry, wgConfig WgConfig, initiator bool) *EndpointUpdater {
	return &EndpointUpdater{
		log:       log,
		wgConfig:  wgConfig,
		initiator: initiator,
	}
}

// ConfigureWGEndpoint sets up the WireGuard endpoint configuration.
// The initiator immediately configures the endpoint, while the non-initiator
// waits for a fallback period before configuring to avoid handshake congestion.
func (e *EndpointUpdater) ConfigureWGEndpoint(addr *net.UDPAddr, presharedKey *wgtypes.Key) error {
	if e.initiator {
		return e.updateWireGuardPeer(addr, presharedKey)
	}

	// prevent to run new update while cancel the previous update
	e.configUpdateMutex.Lock()
	if e.cancelFunc != nil {
		e.cancelFunc()
	}
	e.configUpdateMutex.Unlock()

	var ctx context.Context
	ctx, e.cancelFunc = context.WithCancel(context.Background())
	go e.scheduleDelayedUpdate(ctx, addr, presharedKey)

	return e.updateWireGuardPeer(nil, presharedKey)
}

func (e *EndpointUpdater) removeWgPeer() error {
	e.configUpdateMutex.Lock()
	defer e.configUpdateMutex.Unlock()

	if e.cancelFunc != nil {
		e.cancelFunc()
	}

	return e.wgConfig.WgInterface.RemovePeer(e.wgConfig.RemoteKey)
}

// scheduleDelayedUpdate waits for the fallback period before updating the endpoint
func (e *EndpointUpdater) scheduleDelayedUpdate(ctx context.Context, addr *net.UDPAddr, presharedKey *wgtypes.Key) {
	t := time.NewTimer(fallbackDelay)
	defer t.Stop()

	select {
	case <-ctx.Done():
		return
	case <-t.C:
		e.configUpdateMutex.Lock()
		defer e.configUpdateMutex.Unlock()

		if ctx.Err() != nil {
			return
		}

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
