//go:build !windows

package uspfilter

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/statemanager"
)

// Reset firewall to the default state
func (m *Manager) Close(stateManager *statemanager.Manager) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.outgoingRules = make(map[string]RuleSet)
	m.incomingRules = make(map[string]RuleSet)

	if m.udpTracker != nil {
		m.udpTracker.Close()
	}

	if m.icmpTracker != nil {
		m.icmpTracker.Close()
	}

	if m.tcpTracker != nil {
		m.tcpTracker.Close()
	}

	if m.forwarder != nil {
		m.forwarder.Stop()
	}

	if m.logger != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := m.logger.Stop(ctx); err != nil {
			log.Errorf("failed to shutdown logger: %v", err)
		}
	}

	if m.nativeFirewall != nil {
		return m.nativeFirewall.Close(stateManager)
	}
	return nil
}

// AllowNetbird allows netbird interface traffic
func (m *Manager) AllowNetbird() error {
	if m.nativeFirewall != nil {
		return m.nativeFirewall.AllowNetbird()
	}
	return nil
}
