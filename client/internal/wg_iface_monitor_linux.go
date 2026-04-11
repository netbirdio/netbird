//go:build linux

package internal

import (
	"context"
	"fmt"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// watchInterface uses an RTNLGRP_LINK netlink subscription to detect
// deletion or recreation of the WireGuard interface.
//
// The previous implementation polled net.InterfaceByName every 2 s, which
// on Linux issues syscall.NetlinkRIB(RTM_GETLINK, ...) and dumps the
// entire kernel link table on every call. On hosts with many veth
// interfaces (containers, bridges) the resulting allocation churn was on
// the order of ~1 GB/day from this single ticker, which on small ARM
// hosts manifested as a slow RSS climb (see netbirdio/netbird#3678).
//
// The event-driven version below allocates only when the kernel actually
// publishes a link event for the tracked interface — typically zero
// allocations between events.
func watchInterface(ctx context.Context, ifaceName string, expectedIndex int) (bool, error) {
	done := make(chan struct{})
	defer close(done)

	// Buffer the channel to absorb event bursts (e.g. when many veth
	// pairs are created/destroyed at once by container runtimes).
	linkChan := make(chan netlink.LinkUpdate, 32)
	if err := netlink.LinkSubscribe(linkChan, done); err != nil {
		return false, fmt.Errorf("subscribe to link updates: %w", err)
	}

	// Race window: the interface could have been deleted (or recreated)
	// between the initial getInterfaceIndex() in Start and LinkSubscribe
	// completing its handshake with the kernel. Re-check explicitly so we
	// do not block forever waiting for an event that already fired.
	if currentIndex, err := getInterfaceIndex(ifaceName); err != nil {
		log.Infof("Interface monitor: %s deleted before subscription completed", ifaceName)
		return true, fmt.Errorf("interface %s deleted: %w", ifaceName, err)
	} else if currentIndex != expectedIndex {
		log.Infof("Interface monitor: %s recreated (index changed from %d to %d) before subscription completed",
			ifaceName, expectedIndex, currentIndex)
		return true, nil
	}

	for {
		select {
		case <-ctx.Done():
			log.Infof("Interface monitor: stopped for %s", ifaceName)
			return false, fmt.Errorf("wg interface monitor stopped: %v", ctx.Err())

		case update, ok := <-linkChan:
			if !ok {
				return false, fmt.Errorf("link subscription channel closed unexpectedly")
			}

			eventIndex := int(update.Index)
			eventType := update.Header.Type
			eventName := ""
			if attrs := update.Attrs(); attrs != nil {
				eventName = attrs.Name
			}

			switch eventType {
			case syscall.RTM_DELLINK:
				if eventIndex == expectedIndex {
					log.Infof("Interface monitor: %s deleted", ifaceName)
					return true, fmt.Errorf("interface %s deleted", ifaceName)
				}
			case syscall.RTM_NEWLINK:
				// Recreation: a new link with our name appears at a
				// different index. Same name + same index is just a
				// flag/state change on the existing interface — ignore.
				if eventName == ifaceName && eventIndex != expectedIndex {
					log.Infof("Interface monitor: %s recreated (index changed from %d to %d), restarting engine",
						ifaceName, expectedIndex, eventIndex)
					return true, nil
				}
			}
		}
	}
}
