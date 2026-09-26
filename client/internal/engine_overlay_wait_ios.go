//go:build ios

package internal

import (
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	overlayWatchInterval = 200 * time.Millisecond
	overlayWatchTimeout  = time.Minute
)

// overlayWaiter holds what waits for the overlay address, keyed by name so a
// second arming of the same subsystem replaces it. Guarded by syncMsgMux.
type overlayWaiter struct {
	watching bool
	waiters  map[string]overlayRebind
}

// overlayAddrReady reports whether ip is on the tunnel interface as it is now.
//
// The engine learning its overlay address is not the same as the address being
// usable. iOS does not let the client touch the interface: it hands the engine
// a tun fd and applies the address itself, out of band and without telling the
// engine when it lands. A bind placed in between fails with EADDRNOTAVAIL, and
// the listener has no way back on its own. The caller must hold syncMsgMux.
func (e *Engine) overlayAddrReady(ip netip.Addr) bool {
	if e.wgInterface == nil || !ip.IsValid() {
		return false
	}

	iface, err := net.InterfaceByName(e.wgInterface.Name())
	if err != nil {
		log.Debugf("look up tunnel interface %s: %v", e.wgInterface.Name(), err)
		return false
	}
	addrs, err := iface.Addrs()
	if err != nil {
		log.Debugf("list addresses of %s: %v", e.wgInterface.Name(), err)
		return false
	}

	for _, addr := range addrs {
		prefix, err := netip.ParsePrefix(addr.String())
		if err != nil {
			continue
		}
		if prefix.Addr().Unmap() == ip.Unmap() {
			return true
		}
	}
	return false
}

// armOverlayWatch waits for the overlay address to appear and then binds what
// asked to be bound.
//
// Only the subsystems that armed the watch are bound. This is deliberately
// narrower than rebindOverlayListeners: an address that was missing says
// nothing about the listeners that did come up, and rebuilding those would drop
// the SSH sessions and DNS queries they are carrying. The caller must hold
// syncMsgMux.
func (e *Engine) armOverlayWatch(name string, ensure overlayRebind) {
	if e.ctx.Err() != nil {
		return
	}

	if e.overlayWait.waiters == nil {
		e.overlayWait.waiters = make(map[string]overlayRebind)
	}
	e.overlayWait.waiters[name] = ensure

	if e.overlayWait.watching {
		return
	}
	e.overlayWait.watching = true

	e.shutdownWg.Add(1)
	go func() {
		defer e.shutdownWg.Done()

		ticker := time.NewTicker(overlayWatchInterval)
		defer ticker.Stop()
		deadline := time.NewTimer(overlayWatchTimeout)
		defer deadline.Stop()

		for {
			select {
			case <-e.ctx.Done():
				return
			case <-deadline.C:
				e.syncMsgMux.Lock()
				waiting := slices.Sorted(maps.Keys(e.overlayWait.waiters))
				e.overlayWait = overlayWaiter{}
				e.syncMsgMux.Unlock()
				log.Errorf("overlay address did not appear within %s, still down: %s",
					overlayWatchTimeout, strings.Join(waiting, ", "))
				return
			case <-ticker.C:
				if e.bindOverlayWaiters() {
					return
				}
			}
		}
	}()
}

// bindOverlayWaiters runs what the watch collected once the overlay address is
// up, reporting whether the wait is over.
func (e *Engine) bindOverlayWaiters() bool {
	e.syncMsgMux.Lock()
	defer e.syncMsgMux.Unlock()

	if e.wgInterface == nil || !e.overlayAddrReady(e.wgInterface.Address().IP) {
		return false
	}

	waiters := e.overlayWait.waiters
	e.overlayWait = overlayWaiter{}

	for name, ensure := range waiters {
		log.Infof("overlay address is up, binding %s", name)
		if err := ensure(); err != nil {
			log.Errorf("bind %s after the overlay address came up: %v", name, err)
		}
	}
	return true
}
