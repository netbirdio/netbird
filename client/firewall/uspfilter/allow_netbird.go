//go:build !windows

package uspfilter

import (
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/firewall/firewalld"
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
	if err := firewalld.UntrustInterface(m.wgIface.Name()); err != nil {
		log.Warnf("failed to untrust interface in firewalld: %v", err)
	}
	return nil
}

// AllowNetbird allows netbird interface traffic
func (m *Manager) AllowNetbird() error {
	if m.nativeFirewall != nil {
		return m.nativeFirewall.AllowNetbird()
	}
	if err := firewalld.TrustInterface(m.wgIface.Name()); err != nil {
		log.Warnf("failed to trust interface in firewalld: %v", err)
	}
	return nil
}
