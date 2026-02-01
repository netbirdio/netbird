//go:build !darwin || ios

package proxy

import (
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

// ShutdownState is a no-op state for non-macOS platforms.
type ShutdownState struct{}

// Name returns the state name.
func (s *ShutdownState) Name() string {
	return "proxy_state"
}

// Cleanup is a no-op on non-macOS platforms.
func (s *ShutdownState) Cleanup() error {
	return nil
}

// RegisterState is a no-op on non-macOS platforms.
func RegisterState(stateManager *statemanager.Manager) {
}
