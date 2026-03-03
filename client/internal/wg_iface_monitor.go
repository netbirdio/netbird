package internal

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"time"

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

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Infof("Interface monitor: stopped for %s", ifaceName)
			return false, fmt.Errorf("wg interface monitor stopped: %v", ctx.Err())
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
