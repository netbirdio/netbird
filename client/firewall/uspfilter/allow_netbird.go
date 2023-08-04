//go:build !windows

package uspfilter

// AllowNetbird allows netbird interface traffic
func (m *Manager) AllowNetbird() error {
	return nil
}
