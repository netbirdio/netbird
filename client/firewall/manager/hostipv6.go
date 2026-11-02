package manager

import (
	"os"
	"strings"
)

const (
	procIfInet6        = "/proc/net/if_inet6"
	procDisableIPv6All = "/proc/sys/net/ipv6/conf/all/disable_ipv6"
	procDisableIPv6Def = "/proc/sys/net/ipv6/conf/default/disable_ipv6"
)

// HostHasIPv6 reports whether the host kernel can receive IPv6 on a new interface.
//
// It is false only when the kernel has no IPv6 support, or IPv6 is disabled for both the
// existing and the future interfaces. A value that cannot be read counts as enabled, so
// callers that use this to decide whether IPv6 has to be filtered err on the side of filtering.
func HostHasIPv6() bool {
	if _, err := os.Stat(procIfInet6); err != nil {
		return false
	}
	return !sysctlIsOne(procDisableIPv6All) || !sysctlIsOne(procDisableIPv6Def)
}

func sysctlIsOne(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == "1"
}
