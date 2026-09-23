package uspfilter

import (
	"net"
	"net/netip"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

// countRulesForAddr reports how many rules in the given slice match
// the supplied source address.
func countRulesForAddr(rules peerRules, src netip.Addr) int {
	n := 0
	for _, r := range rules {
		if r.matchesSource(src) {
			n++
		}
	}
	return n
}

// findRuleByID returns true if the rules slice contains a rule with
// the given id whose source set covers src.
func findRuleByID(rules peerRules, src netip.Addr, id firewall.RuleID) bool {
	for _, r := range rules {
		if r.id == id && r.matchesSource(src) {
			return true
		}
	}
	return false
}

// pfx converts a single net.IP into the []netip.Prefix form
// AddFilterRule expects. A nil or unspecified address becomes a /0
// ("match any") prefix in the matching family; any other address
// becomes its /32 (or /128) host prefix.
func pfx(ip net.IP) []netip.Prefix {
	if ip == nil {
		return []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0)}
	}
	if ip.IsUnspecified() {
		if ip.To4() != nil {
			return []netip.Prefix{netip.PrefixFrom(netip.IPv4Unspecified(), 0)}
		}
		return []netip.Prefix{netip.PrefixFrom(netip.IPv6Unspecified(), 0)}
	}
	a, _ := netip.AddrFromSlice(ip)
	a = a.Unmap()
	return []netip.Prefix{netip.PrefixFrom(a, a.BitLen())}
}
