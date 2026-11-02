package manager

import (
	"errors"
	"io/fs"
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// EnvAllowUnfilteredIPv6 leaves IPv6 arriving on the interface to the host's own rules when the
// interface has no IPv6 overlay address, instead of dropping it.
const EnvAllowUnfilteredIPv6 = "NB_ALLOW_UNFILTERED_IPV6"

const (
	procIfInet6        = "/proc/net/if_inet6"
	procDisableIPv6All = "/proc/sys/net/ipv6/conf/all/disable_ipv6"
	procDisableIPv6Def = "/proc/sys/net/ipv6/conf/default/disable_ipv6"
)

// HostHasIPv6 reports whether the host kernel can receive IPv6 on a new interface.
//
// It is false only when the kernel has no IPv6 support, or IPv6 is disabled for both the
// existing and the future interfaces. Anything that cannot be told, such as a procfs entry that
// cannot be read, counts as enabled, so callers that use this to decide whether IPv6 has to be
// filtered err on the side of filtering.
func HostHasIPv6() bool {
	if _, err := os.Stat(procIfInet6); errors.Is(err, fs.ErrNotExist) {
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

// AllowUnfilteredIPv6 reports whether the operator asked, through EnvAllowUnfilteredIPv6, for IPv6
// on an interface without an IPv6 overlay address to be left to the host's rules. A value that is
// not a boolean is logged and ignored, so the IPv6 deny stays in place.
func AllowUnfilteredIPv6() bool {
	val := os.Getenv(EnvAllowUnfilteredIPv6)
	if val == "" {
		return false
	}
	allow, err := strconv.ParseBool(val)
	if err != nil {
		log.Warnf("failed to parse %s: %v", EnvAllowUnfilteredIPv6, err)
		return false
	}
	return allow
}
