// Package dnsfw blocks DNS traffic from non-netbird processes when netbird is
// managing the host's DNS, so that resolvers running on apps or libraries
// outside netbird cannot bypass the configured DNS path.
//
// Implementation is Windows-only (uses WFP). On other platforms New returns
// a no-op manager.
package dnsfw

import "net/netip"

// Manager controls the per-tunnel DNS firewall. Both methods must be safe
// to call multiple times.
type Manager interface {
	Enable(ifaceGUID string, virtualDNSIP netip.Addr) error
	Disable() error
}
