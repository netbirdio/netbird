//go:build linux && !android

package watcher

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"

	"github.com/vishvananda/netlink"
)

type netlinkWatcher struct {
	netbirdIface string

	mu         sync.Mutex
	lastLinkUp bool
	cancel     context.CancelFunc
	done       chan struct{}
}

func newNetlinkWatcher(netbirdIface string) *netlinkWatcher {
	return &netlinkWatcher{
		netbirdIface: netbirdIface,
		done:         make(chan struct{}),
	}
}

// Start begins listening to netlink link and route updates.
func (w *netlinkWatcher) Start(ctx context.Context, handler Handler) error {
	w.mu.Lock()
	if w.cancel != nil {
		w.mu.Unlock()
		return errors.New("netlink watcher already started")
	}

	ctx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	w.mu.Unlock()

	defer close(w.done)

	linkChan := make(chan netlink.LinkUpdate, 32)
	routeChan := make(chan netlink.RouteUpdate, 32)
	linkDone := make(chan struct{})
	routeDone := make(chan struct{})
	defer close(linkDone)
	defer close(routeDone)

	if err := netlink.LinkSubscribe(linkChan, linkDone); err != nil {
		return fmt.Errorf("subscribe to link updates: %w", err)
	}
	if err := netlink.RouteSubscribe(routeChan, routeDone); err != nil {
		return fmt.Errorf("subscribe to route updates: %w", err)
	}

	if iface, err := net.InterfaceByName(w.netbirdIface); err == nil && iface.Flags&net.FlagUp != 0 {
		w.mu.Lock()
		w.lastLinkUp = true
		w.mu.Unlock()
	}

	if routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL); err == nil {
		hasDefault := false
		for _, r := range routes {
			if isDefaultRoute(r.Dst) && r.Table == syscall.RT_TABLE_MAIN {
				hasDefault = true
				break
			}
		}
		if !hasDefault && handler != nil {
			handler.OnNetworkEvent(Event{
				Kind:   EventNetworkDisconnected,
				Reason: "no default route on startup",
			})
		}
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case update, ok := <-linkChan:
			if !ok {
				return nil
			}
			w.handleLinkUpdate(update, handler)

		case update, ok := <-routeChan:
			if !ok {
				return nil
			}
			w.handleRouteUpdate(update, handler)
		}
	}
}

// Stop terminates the netlink subscriptions.
func (w *netlinkWatcher) Stop() error {
	w.mu.Lock()
	cancel := w.cancel
	w.mu.Unlock()

	if cancel != nil {
		cancel()
		<-w.done
	}
	return nil
}

func (w *netlinkWatcher) handleLinkUpdate(update netlink.LinkUpdate, handler Handler) {
	attrs := update.Attrs()
	if attrs == nil || attrs.Name != w.netbirdIface {
		return
	}

	w.mu.Lock()
	wasUp := w.lastLinkUp
	isUp := attrs.Flags&net.FlagUp != 0
	w.lastLinkUp = isUp
	w.mu.Unlock()

	if wasUp && !isUp {
		handler.OnNetworkEvent(Event{
			Kind:          EventNetBirdInterfaceDisconnected,
			Name:          attrs.Name,
			Reason:        "interface IFF_UP flag cleared",
			UserInitiated: false,
		})
	} else if !wasUp && isUp {
		handler.OnNetworkEvent(Event{
			Kind:   EventNetworkConnected,
			Name:   attrs.Name,
			Reason: "interface IFF_UP flag set",
		})
	}
}

func isDefaultRoute(dst *net.IPNet) bool {
	if dst == nil {
		return true
	}
	ones, bits := dst.Mask.Size()
	return ones == 0 && (bits == 32 || bits == 128)
}

func (w *netlinkWatcher) handleRouteUpdate(update netlink.RouteUpdate, handler Handler) {
	if !isDefaultRoute(update.Dst) || update.Table != syscall.RT_TABLE_MAIN {
		return
	}
	switch update.Type {
	case syscall.RTM_DELROUTE:
		routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
		if err != nil {
			return
		}
		hasDefault := false
		for _, r := range routes {
			if isDefaultRoute(r.Dst) && r.Table == syscall.RT_TABLE_MAIN {
				hasDefault = true
				break
			}
		}
		if !hasDefault {
			handler.OnNetworkEvent(Event{
				Kind:   EventNetworkDisconnected,
				Reason: "default route removed",
			})
		}
	case syscall.RTM_NEWROUTE:
		handler.OnNetworkEvent(Event{
			Kind:   EventNetworkConnected,
			Reason: "default route added",
		})
	}
}
