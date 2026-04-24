//go:build !windows

package uspfilter

import (
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

// Close cleans up the firewall manager by removing all rules and closing trackers
func (m *Manager) Close(stateManager *statemanager.Manager) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.resetState()

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
