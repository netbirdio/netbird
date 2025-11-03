//go:build !windows && !darwin

package updatemanager

import "context"

func (m *Manager) triggerUpdate(ctx context.Context, targetVersion string) error {
	// TODO: Implement
	return nil
}
