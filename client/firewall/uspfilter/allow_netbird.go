//go:build !windows

package uspfilter

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/client/internal/statemanager"
)

// Close cleans up the firewall manager by removing all rules and closing trackers
func (m *Manager) Close(stateManager *statemanager.Manager) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	maps.Clear(m.outgoingRules)
	maps.Clear(m.incomingDenyRules)
	maps.Clear(m.incomingRules)
	maps.Clear(m.routeRulesMap)
	m.routeRules = m.routeRules[:0]

	if m.udpTracker != nil {
		m.udpTracker.Close()
	}

	if m.icmpTracker != nil {
		m.icmpTracker.Close()
	}

	if m.tcpTracker != nil {
		m.tcpTracker.Close()
	}

	if fwder := m.forwarder.Load(); fwder != nil {
		fwder.Stop()
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
