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

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
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
	if attrs == nil {
		return
	}
	if attrs.Name == w.netbirdIface {
		if attrs.Flags&net.FlagUp == 0 {
			handler.OnNetworkEvent(Event{
				Kind:          EventNetBirdInterfaceDisconnected,
				Name:          attrs.Name,
				Reason:        "interface IFF_UP flag cleared",
				UserInitiated: false,
			})
		}
	}
}

func (w *netlinkWatcher) handleRouteUpdate(update netlink.RouteUpdate, handler Handler) {
	if update.Dst != nil || update.Table != syscall.RT_TABLE_MAIN {
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
			if r.Dst == nil && r.Table == syscall.RT_TABLE_MAIN {
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
