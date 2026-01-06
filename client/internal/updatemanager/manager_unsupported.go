//go:build !windows && !darwin

package updatemanager

import (
	"context"
	"fmt"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

// Manager is a no-op stub for unsupported platforms
type Manager struct{}

// NewManager returns a no-op manager for unsupported platforms
func NewManager(statusRecorder *peer.Status, stateManager *statemanager.Manager) (*Manager, error) {
	return nil, fmt.Errorf("update manager is not supported on this platform")
}

// CheckUpdateSuccess is a no-op on unsupported platforms
func (m *Manager) CheckUpdateSuccess(ctx context.Context) {
	// no-op
}

// Start is a no-op on unsupported platforms
func (m *Manager) Start(ctx context.Context) {
	// no-op
}

// SetVersion is a no-op on unsupported platforms
func (m *Manager) SetVersion(expectedVersion string) {
	// no-op
}

// Stop is a no-op on unsupported platforms
func (m *Manager) Stop() {
	// no-op
}
