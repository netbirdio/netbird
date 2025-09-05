package peer

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// fallbackDelay could be const but because of testing it is a var
var fallbackDelay = 5 * time.Second

type endpointUpdater struct {
	log       *logrus.Entry
	wgConfig  WgConfig
	initiator bool

	cancelFunc        func()
	configUpdateMutex sync.Mutex
}

// configureWGEndpoint sets up the WireGuard endpoint configuration.
// The initiator immediately configures the endpoint, while the non-initiator
// waits for a fallback period before configuring to avoid handshake congestion.
func (e *endpointUpdater) configureWGEndpoint(addr *net.UDPAddr, remoteRPKey []byte) error {
	if e.initiator {
		return e.updateWireGuardPeer(addr, remoteRPKey)
	}

	// prevent to run new update while cancel the previous update
	e.configUpdateMutex.Lock()
	if e.cancelFunc != nil {
		e.cancelFunc()
	}
	e.configUpdateMutex.Unlock()

	var ctx context.Context
	ctx, e.cancelFunc = context.WithCancel(context.Background())
	go e.scheduleDelayedUpdate(ctx, addr, remoteRPKey)

	return e.updateWireGuardPeer(nil, remoteRPKey)
}

func (e *endpointUpdater) removeWgPeer() error {
	e.configUpdateMutex.Lock()
	defer e.configUpdateMutex.Unlock()

	if e.cancelFunc != nil {
		e.cancelFunc()
	}

	return e.wgConfig.WgInterface.RemovePeer(e.wgConfig.RemoteKey)
}

// scheduleDelayedUpdate waits for the fallback period before updating the endpoint
func (e *endpointUpdater) scheduleDelayedUpdate(ctx context.Context, addr *net.UDPAddr, remoteRPKey []byte) {
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

		if err := e.updateWireGuardPeer(addr, remoteRPKey); err != nil {
			e.log.Errorf("failed to update WireGuard peer, address: %s, error: %v", addr, err)
		}
	}
}

func (e *endpointUpdater) updateWireGuardPeer(endpoint *net.UDPAddr, remoteRPKey []byte) error {
	// todo add, "presharedKey := e.presharedKey(remote)"
	return e.wgConfig.WgInterface.UpdatePeer(
		e.wgConfig.RemoteKey,
		e.wgConfig.AllowedIps,
		defaultWgKeepAlive,
		endpoint,
		e.wgConfig.PreSharedKey,
	)
}
