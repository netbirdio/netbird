//go:build darwin

package systemops

import "golang.org/x/sys/unix"

// IgnoreAddedDefaultRoute reports whether an RTM_ADD default route with the
// given flags should be ignored by the network monitor. Scoped routes
// (RTF_IFSCOPE) are tied to a specific interface index and cannot replace the
// unscoped default the kernel uses for general egress, so flapping ones (e.g.
// Wi-Fi calling IMS tunnels on ipsec0, Docker bridges, scoped utun defaults)
// must not trigger an engine restart.
func IgnoreAddedDefaultRoute(flags int) bool {
	if filterRoutesByFlags(flags) {
		return true
	}
	if flags&unix.RTF_IFSCOPE != 0 {
		return true
	}
	return false
}
