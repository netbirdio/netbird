//go:build !darwin || ios

package proxy

import (
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

// Manager is a no-op proxy manager for non-macOS platforms.
type Manager struct{}

// NewManager creates a new proxy manager (no-op on non-macOS).
func NewManager(_ *statemanager.Manager) *Manager {
	return &Manager{}
}

// EnableWebProxy is a no-op on non-macOS platforms.
func (m *Manager) EnableWebProxy(host string, port int) error {
	return nil
}

// DisableWebProxy is a no-op on non-macOS platforms.
func (m *Manager) DisableWebProxy() error {
	return nil
}

// SetAutoproxyURL is a no-op on non-macOS platforms.
func (m *Manager) SetAutoproxyURL(pacURL string) error {
	return nil
}

// DisableAutoproxy is a no-op on non-macOS platforms.
func (m *Manager) DisableAutoproxy() error {
	return nil
}

// IsEnabled always returns false on non-macOS platforms.
func (m *Manager) IsEnabled() bool {
	return false
}

// Restore is a no-op on non-macOS platforms.
func (m *Manager) Restore(services []string) error {
	return nil
}
