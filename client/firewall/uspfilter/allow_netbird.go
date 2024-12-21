//go:build !windows

package uspfilter

import (
	"github.com/netbirdio/netbird/client/firewall/uspfilter/conntrack"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

// Reset firewall to the default state
func (m *Manager) Reset(stateManager *statemanager.Manager) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.outgoingRules = make(map[string]RuleSet)
	m.incomingRules = make(map[string]RuleSet)

	if m.udpTracker != nil {
		m.udpTracker.Close()
		m.udpTracker = conntrack.NewUDPTracker(conntrack.DefaultUDPTimeout)
	}

	if m.icmpTracker != nil {
		m.icmpTracker.Close()
		m.icmpTracker = conntrack.NewICMPTracker(conntrack.DefaultICMPTimeout)
	}

	if m.tcpTracker != nil {
		m.tcpTracker.Close()
		m.tcpTracker = conntrack.NewTCPTracker(conntrack.DefaultTCPTimeout)
	}

	if m.nativeFirewall != nil {
		return m.nativeFirewall.Reset(stateManager)
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
