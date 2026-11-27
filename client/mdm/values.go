package mdm

import (
	"math"
	"net/netip"
	"regexp"
	"runtime"
	"strings"
	"unicode"

	log "github.com/sirupsen/logrus"
)

// MTU bounds a managed mtu must fall in. They mirror iface.MinMTU and
// iface.MaxMTU, kept here so this package does not pull in the interface code.
const (
	MinMTU = 576
	MaxMTU = 8192
)

// utunNameRe matches the only interface names macOS accepts: utun plus the unit number.
var utunNameRe = regexp.MustCompile(`^utun\d+$`)

// boolKeys are the keys read as a boolean.
var boolKeys = []string{
	KeyDisableUpdateSettings, KeyDisableProfiles, KeyDisableNetworks, KeyDisableAdvancedView,
	KeyDisableClientRoutes, KeyDisableServerRoutes, KeyBlockInbound, KeyDisableMetricsCollection,
	KeyAllowServerSSH, KeyDisableAutoConnect, KeyDisableAutostart, KeyRosenpassEnabled,
	KeyRosenpassPermissive, KeyEnableLocalMetrics, KeyLazyConnection, KeyRemoteJobsAllowed,
	KeyDisableDNS, KeyDisableIPv6, KeyDisableFirewall, KeyBlockLANAccess, KeyDisableNotifications,
	KeyNetworkMonitor, KeyDisableIPv6Discovery, KeyForceRelay, KeyEnableSSHRoot, KeyEnableSSHSFTP,
	KeyEnableSSHLocalPortForwarding, KeyEnableSSHRemotePortForwarding, KeyDisableSSHAuth,
	KeyKeepConnectedOnQuit, KeyAllowServerVNC, KeyDisableVNCApproval,
}

// securityBoolFallbacks holds the restrictive value of each security boolean.
// An unreadable one is locked to that value instead of being dropped: the
// client cannot tell what the administrator meant, and leaving the setting to
// the user could open what the policy was there to close.
var securityBoolFallbacks = map[string]bool{
	KeyBlockInbound:                  true,
	KeyBlockLANAccess:                true,
	KeyDisableFirewall:               false,
	KeyDisableSSHAuth:                false,
	KeyAllowServerSSH:                false,
	KeyAllowServerVNC:                false,
	KeyDisableVNCApproval:            false,
	KeyRemoteJobsAllowed:             false,
	KeyEnableSSHRoot:                 false,
	KeyEnableSSHSFTP:                 false,
	KeyEnableSSHLocalPortForwarding:  false,
	KeyEnableSSHRemotePortForwarding: false,
	KeyEnableLocalMetrics:            false,
}

// valueChecks decides whether a value is usable. A key with an unusable value
// is dropped as if the policy did not set it, so the user keeps control of the
// setting instead of having it locked to a value nothing applies.
var valueChecks = map[string]func(p *Policy, key string) bool{
	KeyWireguardPort:       intIn(1, math.MaxUint16),
	KeyMTU:                 usableMTU,
	KeySSHJWTCacheTTL:      intIn(0, math.MaxInt32),
	KeyDNSRouteInterval:    positiveDuration,
	KeyInterfaceName:       usableInterfaceName,
	KeyNATExternalIPs:      natMappings,
	KeyExtraIFaceBlackList: stringList,
}

// IsUtunName reports whether name is an interface name macOS accepts.
func IsUtunName(name string) bool {
	return utunNameRe.MatchString(name)
}

// dropUnusableValues removes the keys whose value cannot be applied, logging
// each one so the administrator can find the typo. An unreadable security
// boolean is the exception: it is locked to its restrictive value instead.
func dropUnusableValues(values map[string]any) map[string]any {
	p := &Policy{values: values}
	var drop, restrict []string
	for key, usable := range valueChecks {
		if p.HasKey(key) && !usable(p, key) {
			drop = append(drop, key)
		}
	}
	for _, key := range boolKeys {
		if !p.HasKey(key) || boolean(p, key) {
			continue
		}
		if _, ok := securityBoolFallbacks[key]; ok {
			restrict = append(restrict, key)
			continue
		}
		drop = append(drop, key)
	}
	if len(drop) == 0 && len(restrict) == 0 {
		return values
	}
	kept := make(map[string]any, len(values))
	for k, v := range values {
		kept[k] = v
	}
	for _, key := range drop {
		log.Warnf("MDM %s has an unusable value; ignoring the key, the user keeps control of it", key)
		log.Debugf("MDM %s unusable value: %v", key, values[key])
		delete(kept, key)
	}
	for _, key := range restrict {
		log.Warnf("MDM %s has an unreadable value; enforcing the restrictive value %t", key, securityBoolFallbacks[key])
		log.Debugf("MDM %s unreadable value: %v", key, values[key])
		kept[key] = securityBoolFallbacks[key]
	}
	return kept
}

func intIn(lo, hi int64) func(*Policy, string) bool {
	return func(p *Policy, key string) bool {
		v, ok := p.GetInt(key)
		return ok && v >= lo && v <= hi
	}
}

// usableMTU refuses every value on iOS and tvOS, whose tunnel MTU is fixed by
// the app: a different interface MTU would not match it.
func usableMTU(p *Policy, key string) bool {
	return runtime.GOOS != "ios" && intIn(MinMTU, MaxMTU)(p, key)
}

func positiveDuration(p *Policy, key string) bool {
	d, ok := p.GetDuration(key)
	return ok && d > 0
}

func usableInterfaceName(p *Policy, key string) bool {
	name, ok := p.GetString(key)
	if !ok {
		return false
	}
	switch runtime.GOOS {
	case "darwin":
		return IsUtunName(name)
	case "linux":
		return isLinuxInterfaceName(name)
	}
	return true
}

// isLinuxInterfaceName mirrors the kernel's dev_valid_name: at most 15 bytes,
// not "." or "..", and no slash, colon or whitespace. A '%' is refused too: the
// kernel expands it as a unit number, so the interface gets another name.
func isLinuxInterfaceName(name string) bool {
	if name == "" || len(name) > 15 || name == "." || name == ".." {
		return false
	}
	return !strings.ContainsFunc(name, func(r rune) bool {
		return r == '/' || r == ':' || r == '%' || unicode.IsSpace(r)
	})
}

func boolean(p *Policy, key string) bool {
	_, ok := p.GetBool(key)
	return ok
}

// natMappings accepts external-IP[/internal-IP or /interface] entries, the form
// the engine parses; the engine drops every mapping when one is malformed. An
// empty list is usable: it enforces no mappings.
func natMappings(p *Policy, key string) bool {
	values, ok := p.GetStringSlice(key)
	if !ok {
		return false
	}
	for _, entry := range SplitList(values) {
		external, internal, hasInternal := strings.Cut(entry, "/")
		if !isPlainIP(external) {
			return false
		}
		if hasInternal && !isNATInternal(internal) {
			return false
		}
	}
	return true
}

// isPlainIP reports whether s is an address the engine's net.ParseIP reads,
// which refuses an IPv6 zone.
func isPlainIP(s string) bool {
	addr, err := netip.ParseAddr(s)
	return err == nil && addr.Zone() == ""
}

// isNATInternal accepts an address or an interface name. A zoned address or a
// bare number is neither: the engine looks it up as an interface and fails,
// which is how a CIDR such as 203.0.113.10/32 slips past a looser check.
func isNATInternal(s string) bool {
	if s == "" || strings.Contains(s, "/") {
		return false
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Zone() == ""
	}
	return strings.ContainsFunc(s, func(r rune) bool { return !unicode.IsDigit(r) })
}

func stringList(p *Policy, key string) bool {
	_, ok := p.GetStringSlice(key)
	return ok
}
