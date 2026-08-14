//go:build !windows

package dnsfw

import "net/netip"

type noopManager struct{}

func (noopManager) Enable(string, netip.Addr) error { return nil }
func (noopManager) Disable() error                  { return nil }

// New returns a no-op manager on non-Windows platforms.
func New() Manager {
	return noopManager{}
}
