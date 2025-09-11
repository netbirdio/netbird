package internal

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"time"

	log "github.com/sirupsen/logrus"
)

// WGIfaceMonitor monitors the WireGuard interface lifecycle and restarts the engine
// if the interface is deleted externally while the engine is running.
type WGIfaceMonitor struct {
	ctx           context.Context
	cancel        context.CancelFunc
	done          chan struct{}
	restartEngine func()
}

// NewWGIfaceMonitor creates a new WGIfaceMonitor instance.
func NewWGIfaceMonitor(restartEngine func()) *WGIfaceMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	return &WGIfaceMonitor{
		ctx:           ctx,
		cancel:        cancel,
		done:          make(chan struct{}),
		restartEngine: restartEngine,
	}
}

// Start begins monitoring the WireGuard interface.
// It relies on the provided context cancellation to stop.
func (m *WGIfaceMonitor) Start(ifaceName string) {
	// Skip on mobile platforms as they handle interface lifecycle differently
	if runtime.GOOS == "android" || runtime.GOOS == "ios" {
		log.Debugf("Interface monitor: skipped on %s platform", runtime.GOOS)
		close(m.done)
		return
	}

	if ifaceName == "" {
		log.Debugf("Interface monitor: empty interface name, skipping monitor")
		close(m.done)
		return
	}

	// Get initial interface index to track the specific interface instance
	initialIndex, err := getInterfaceIndex(ifaceName)
	if err != nil {
		log.Debugf("Interface monitor: interface %s not found, skipping monitor", ifaceName)
		close(m.done)
		return
	}

	go func(ctx context.Context, ifaceName string, expectedIndex int) {
		defer close(m.done)
		log.Infof("Interface monitor: watching %s (index: %d)", ifaceName, expectedIndex)

		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Infof("Interface monitor: stopped for %s", ifaceName)
				return
			case <-ticker.C:
				currentIndex, err := getInterfaceIndex(ifaceName)
				if err != nil {
					// Interface was deleted
					log.Infof("Interface monitor: %s deleted, restarting engine", ifaceName)
					m.restartEngine()
					return
				}

				// Check if interface index changed (interface was recreated)
				if currentIndex != expectedIndex {
					log.Infof("Interface monitor: %s recreated (index changed from %d to %d), restarting engine",
						ifaceName, expectedIndex, currentIndex)
					m.restartEngine()
					return
				}
			}
		}
	}(m.ctx, ifaceName, initialIndex)
}

// Stop stops the monitor and waits for the goroutine to exit.
func (m *WGIfaceMonitor) Stop() {
	log.Debugf("Interface monitor: stopping")
	m.cancel()

	// Wait for the goroutine to exit with a timeout
	select {
	case <-m.done:
		log.Debugf("Interface monitor: stopped gracefully")
	case <-time.After(5 * time.Second):
		log.Warnf("Interface monitor: timeout waiting for goroutine to exit")
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
