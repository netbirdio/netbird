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

	mu                sync.Mutex
	lastLinkUp        bool
	lastNetworkOnline bool
	cancel            context.CancelFunc
	done              chan struct{}

	routeListFn   func() ([]netlink.Route, error)
	linkByIndexFn func(int) (netlink.Link, error)
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

	if link, err := netlink.LinkByName(w.netbirdIface); err == nil && link != nil {
		w.mu.Lock()
		w.lastLinkUp = isLinkOperational(link.Attrs())
		w.mu.Unlock()
	}

	w.mu.Lock()
	w.lastNetworkOnline = w.hasUsableDefaultRoute(nil)
	if !w.lastNetworkOnline && handler != nil {
		handler.OnNetworkEvent(Event{
			Kind:   EventNetworkDisconnected,
			Reason: "no usable default route on startup",
		})
	}
	w.mu.Unlock()

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
		w.handleNetBirdLinkUpdate(attrs, handler)
		return
	}

	if attrs.Flags&net.FlagLoopback != 0 || attrs.Name == "lo" {
		return
	}

	w.handleUnderlyingLinkUpdate(attrs, handler)
}

func (w *netlinkWatcher) handleNetBirdLinkUpdate(attrs *netlink.LinkAttrs, handler Handler) {
	w.mu.Lock()
	wasUp := w.lastLinkUp
	isUp := isLinkOperational(attrs)
	w.lastLinkUp = isUp
	w.mu.Unlock()

	if wasUp && !isUp {
		reason := "interface administrative flag IFF_UP cleared"
		if attrs.Flags&net.FlagUp != 0 {
			reason = "interface carrier or operational state lost"
		}
		handler.OnNetworkEvent(Event{
			Kind:          EventNetBirdInterfaceDisconnected,
			Name:          attrs.Name,
			Reason:        reason,
			UserInitiated: false,
		})
	} else if !wasUp && isUp {
		handler.OnNetworkEvent(Event{
			Kind:   EventNetworkConnected,
			Name:   attrs.Name,
			Reason: "interface operational state restored",
		})
	}
}

func (w *netlinkWatcher) handleUnderlyingLinkUpdate(attrs *netlink.LinkAttrs, handler Handler) {
	usable := w.hasUsableDefaultRoute(attrs)

	w.mu.Lock()
	wasOnline := w.lastNetworkOnline
	w.lastNetworkOnline = usable
	w.mu.Unlock()

	if wasOnline && !usable {
		handler.OnNetworkEvent(Event{
			Kind:   EventNetworkDisconnected,
			Name:   attrs.Name,
			Reason: fmt.Sprintf("underlying link %s lost carrier and no usable default route remaining", attrs.Name),
		})
	} else if !wasOnline && usable {
		handler.OnNetworkEvent(Event{
			Kind:   EventNetworkConnected,
			Name:   attrs.Name,
			Reason: fmt.Sprintf("underlying link %s operational and default route usable", attrs.Name),
		})
	}
}

func isLinkOperational(attrs *netlink.LinkAttrs) bool {
	if attrs == nil {
		return false
	}
	if attrs.Flags&net.FlagUp == 0 {
		return false
	}
	switch attrs.OperState {
	case netlink.OperDown, netlink.OperLowerLayerDown, netlink.OperNotPresent:
		return false
	default:
		return true
	}
}

func isDefaultRoute(dst *net.IPNet) bool {
	if dst == nil {
		return true
	}
	ones, bits := dst.Mask.Size()
	return ones == 0 && (bits == 32 || bits == 128)
}

func (w *netlinkWatcher) hasUsableDefaultRoute(currentAttrs *netlink.LinkAttrs) bool {
	routeList := w.routeListFn
	if routeList == nil {
		routeList = func() ([]netlink.Route, error) {
			return netlink.RouteList(nil, netlink.FAMILY_ALL)
		}
	}
	routes, err := routeList()
	if err != nil {
		return false
	}
	linkByIndex := w.linkByIndexFn
	if linkByIndex == nil {
		linkByIndex = netlink.LinkByIndex
	}

	for _, r := range routes {
		if !isDefaultRoute(r.Dst) || r.Table != syscall.RT_TABLE_MAIN {
			continue
		}
		if r.LinkIndex <= 0 {
			continue
		}
		var attrs *netlink.LinkAttrs
		if currentAttrs != nil && currentAttrs.Index == r.LinkIndex {
			attrs = currentAttrs
		} else {
			link, err := linkByIndex(r.LinkIndex)
			if err != nil || link == nil {
				continue
			}
			attrs = link.Attrs()
		}
		if attrs == nil || attrs.Name == w.netbirdIface {
			continue
		}
		if attrs.Flags&net.FlagLoopback != 0 || attrs.Name == "lo" {
			continue
		}
		if isLinkOperational(attrs) {
			return true
		}
	}
	return false
}

func (w *netlinkWatcher) handleRouteUpdate(update netlink.RouteUpdate, handler Handler) {
	if !isDefaultRoute(update.Dst) || update.Table != syscall.RT_TABLE_MAIN {
		return
	}
	usable := w.hasUsableDefaultRoute(nil)

	w.mu.Lock()
	wasOnline := w.lastNetworkOnline
	w.lastNetworkOnline = usable
	w.mu.Unlock()

	if wasOnline && !usable {
		handler.OnNetworkEvent(Event{
			Kind:   EventNetworkDisconnected,
			Reason: "default route removed or unusable",
		})
	} else if !wasOnline && usable {
		handler.OnNetworkEvent(Event{
			Kind:   EventNetworkConnected,
			Reason: "usable default route restored",
		})
	}
}
