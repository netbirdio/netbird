//go:build !windows

package uspfilter

import "github.com/netbirdio/netbird/client/internal/statemanager"

// Reset firewall to the default state
func (m *Manager) Reset(stateManager *statemanager.Manager) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.outgoingRules = make(map[string]RuleSet)
	m.incomingRules = make(map[string]RuleSet)

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
