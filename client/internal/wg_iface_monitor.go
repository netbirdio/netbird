package internal

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/netstack"
)

// WGIfaceMonitor monitors the WireGuard interface lifecycle and restarts the engine
// if the interface is deleted externally while the engine is running.
type WGIfaceMonitor struct {
	done chan struct{}
}

// NewWGIfaceMonitor creates a new WGIfaceMonitor instance.
func NewWGIfaceMonitor() *WGIfaceMonitor {
	return &WGIfaceMonitor{
		done: make(chan struct{}),
	}
}

// Start begins monitoring the WireGuard interface.
// It relies on the provided context cancellation to stop.
//
// On Linux the watcher is event-driven (RTNLGRP_LINK netlink subscription)
// to avoid the allocation churn of repeatedly dumping the kernel link
// table; on other platforms it falls back to a low-frequency poll.
func (m *WGIfaceMonitor) Start(ctx context.Context, ifaceName string) (shouldRestart bool, err error) {
	defer close(m.done)

	// Skip on mobile platforms as they handle interface lifecycle differently
	if runtime.GOOS == "android" || runtime.GOOS == "ios" {
		log.Debugf("Interface monitor: skipped on %s platform", runtime.GOOS)
		return false, errors.New("not supported on mobile platforms")
	}

	if netstack.IsEnabled() {
		log.Debugf("Interface monitor: skipped in netstack mode")
		return false, nil
	}

	if ifaceName == "" {
		log.Debugf("Interface monitor: empty interface name, skipping monitor")
		return false, errors.New("empty interface name")
	}

	// Get initial interface index to track the specific interface instance
	expectedIndex, err := getInterfaceIndex(ifaceName)
	if err != nil {
		log.Debugf("Interface monitor: interface %s not found, skipping monitor", ifaceName)
		return false, fmt.Errorf("interface %s not found: %w", ifaceName, err)
	}

	log.Infof("Interface monitor: watching %s (index: %d)", ifaceName, expectedIndex)

	return watchInterface(ctx, ifaceName, expectedIndex)
}

// getInterfaceIndex returns the index of a network interface by name.
// Returns an error if the interface is not found.
func getInterfaceIndex(name string) (int, error) {
	if name == "" {
		return 0, fmt.Errorf("empty interface name")
	}
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		// Check if it's specifically a "not found" error
		if errors.Is(err, &net.OpError{}) {
			// On some systems, this might be a "not found" error
			return 0, fmt.Errorf("interface not found: %w", err)
		}
		return 0, fmt.Errorf("failed to lookup interface: %w", err)
	}
	if ifi == nil {
		return 0, fmt.Errorf("interface not found")
	}
	return ifi.Index, nil
}
