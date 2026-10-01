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
		// Return shouldRestart=true so the engine recovers monitoring
		// via triggerClientRestart instead of silently losing it for
		// the rest of the process lifetime.
		return true, fmt.Errorf("subscribe to link updates: %w", err)
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
			return false, fmt.Errorf("wg interface monitor stopped: %w", ctx.Err())

		case update, ok := <-linkChan:
			if !ok {
				// The vishvananda/netlink subscription goroutine closes
				// the channel on receive errors. Signal the engine to
				// restart so monitoring is re-established instead of
				// silently ending.
				log.Warnf("Interface monitor: link subscription channel closed unexpectedly for %s", ifaceName)
				return true, fmt.Errorf("link subscription channel closed unexpectedly")
			}
			if restart, err := inspectLinkEvent(update, ifaceName, expectedIndex); restart {
				return true, err
			}
		}
	}
}

// inspectLinkEvent classifies a single netlink link update against the
// tracked WireGuard interface. It returns (true, err) when the engine
// should restart monitoring; (false, nil) means the event is unrelated
// and the caller should keep waiting.
//
// The error component, when non-nil, describes the kernel-side reason
// (deletion or rename); the recreation case returns (true, nil) since
// no error condition is reported.
func inspectLinkEvent(update netlink.LinkUpdate, ifaceName string, expectedIndex int) (bool, error) {
	eventIndex := int(update.Index)
	eventName := ""
	if attrs := update.Attrs(); attrs != nil {
		eventName = attrs.Name
	}

	switch update.Header.Type {
	case syscall.RTM_DELLINK:
		return inspectDelLink(eventIndex, ifaceName, expectedIndex)
	case syscall.RTM_NEWLINK:
		return inspectNewLink(eventIndex, eventName, ifaceName, expectedIndex)
	}
	return false, nil
}

// inspectDelLink reports a restart when an RTM_DELLINK arrives for the
// tracked interface index.
func inspectDelLink(eventIndex int, ifaceName string, expectedIndex int) (bool, error) {
	if eventIndex != expectedIndex {
		return false, nil
	}
	log.Infof("Interface monitor: %s deleted", ifaceName)
	return true, fmt.Errorf("interface %s deleted", ifaceName)
}

// inspectNewLink reports a restart when an RTM_NEWLINK either:
//
//  1. Introduces a link with our name at a different index (recreation
//     after a delete), or
//
//  2. Reports a link still at our index but with a different name
//     (in-place rename). The previous polling implementation caught
//     this implicitly because net.InterfaceByName(ifaceName) would
//     start failing; the event-driven version has to test it.
//
// Same name + same index is just a flag/state change on the existing
// interface and is ignored.
func inspectNewLink(eventIndex int, eventName, ifaceName string, expectedIndex int) (bool, error) {
	if eventName == ifaceName && eventIndex != expectedIndex {
		log.Infof("Interface monitor: %s recreated (index changed from %d to %d), restarting engine",
			ifaceName, expectedIndex, eventIndex)
		return true, nil
	}
	if eventIndex == expectedIndex && eventName != "" && eventName != ifaceName {
		log.Infof("Interface monitor: %s renamed to %s (index %d), restarting engine",
			ifaceName, eventName, expectedIndex)
		return true, fmt.Errorf("interface %s renamed to %s", ifaceName, eventName)
	}
	return false, nil
}
