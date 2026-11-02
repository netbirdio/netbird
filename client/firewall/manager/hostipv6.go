package manager

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// EnvAllowUnfilteredIPv6 leaves IPv6 arriving on the interface to the host's own rules when the
// interface has no IPv6 overlay address, instead of dropping it.
const EnvAllowUnfilteredIPv6 = "NB_ALLOW_UNFILTERED_IPV6"

const (
	procIfInet6      = "/proc/net/if_inet6"
	procIPv6ConfDir  = "/proc/sys/net/ipv6/conf"
	disableIPv6Entry = "disable_ipv6"
)

// HostHasIPv6 reports whether the named interface can receive IPv6.
//
// It is false only when the kernel has no IPv6 support, or IPv6 is disabled for both the
// existing and the future interfaces and the interface itself has it disabled or, not existing
// yet, inherits that. Writing "all" or "default" does not veto a later per-interface enable, so
// an existing interface with IPv6 enabled counts even when both are set. Anything that cannot be
// told, such as a procfs entry that cannot be read or an unusable name, counts as enabled, so
// callers that use this to decide whether IPv6 has to be filtered err on the side of filtering.
func HostHasIPv6(ifaceName string) bool {
	return hostHasIPv6(procIfInet6, procIPv6ConfDir, ifaceName)
}

func hostHasIPv6(ifInet6, confDir, ifaceName string) bool {
	if _, err := os.Stat(ifInet6); errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if !sysctlIsOne(filepath.Join(confDir, "all", disableIPv6Entry)) ||
		!sysctlIsOne(filepath.Join(confDir, "default", disableIPv6Entry)) {
		return true
	}
	if ifaceName == "" || ifaceName != filepath.Base(ifaceName) || ifaceName == "." || ifaceName == ".." {
		return true
	}

	b, err := os.ReadFile(filepath.Join(confDir, ifaceName, disableIPv6Entry))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// The interface is created with the default, which is disabled.
		return false
	case err != nil:
		return true
	}
	return strings.TrimSpace(string(b)) != "1"
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
