//go:build !linux

package internal

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
)

// watchInterface polls net.InterfaceByName at a fixed interval to detect
// deletion or recreation of the WireGuard interface.
//
// This is the fallback used on non-Linux desktop and server platforms
// (darwin, windows, freebsd). It is also compiled on android and ios so
// the package builds on every supported GOOS, but it is never reached
// at runtime there because Start() in wg_iface_monitor.go exits early
// on mobile platforms.
//
// The Linux build (see wg_iface_monitor_linux.go) uses an event-driven
// RTNLGRP_LINK netlink subscription instead, because on Linux
// net.InterfaceByName issues syscall.NetlinkRIB(RTM_GETLINK, ...) which
// dumps the entire kernel link table on every call and produces
// significant allocation churn (netbirdio/netbird#3678).
//
// Windows is also reported in #3678 as affected by RSS climb. A future
// follow-up could implement an event-driven watcher there using
// NotifyIpInterfaceChange from iphlpapi.
func watchInterface(ctx context.Context, ifaceName string, expectedIndex int) (bool, error) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Infof("Interface monitor: stopped for %s", ifaceName)
			return false, fmt.Errorf("wg interface monitor stopped: %w", ctx.Err())
		case <-ticker.C:
			currentIndex, err := getInterfaceIndex(ifaceName)
			if err != nil {
				// Interface was deleted
				log.Infof("Interface monitor: %s deleted", ifaceName)
				return true, fmt.Errorf("interface %s deleted: %w", ifaceName, err)
			}

			// Check if interface index changed (interface was recreated)
			if currentIndex != expectedIndex {
				log.Infof("Interface monitor: %s recreated (index changed from %d to %d), restarting engine",
					ifaceName, expectedIndex, currentIndex)
				return true, nil
			}
		}
	}
}
