package anonymize

import (
	"encoding/hex"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

const (
	reverseZoneSuffixV4 = ".in-addr.arpa"
	reverseZoneSuffixV6 = ".ip6.arpa"

	v6Nibbles = 32
	v4Octets  = 4
)

// reverseZoneRegexes match a reverse zone or a full reverse name in free text.
// They are applied before the address passes of AnonymizeString, whose IPv4
// pattern would otherwise consume the digit labels of a zone and replace parts
// of it with unrelated addresses.
var reverseZoneRegexes = []*regexp.Regexp{
	regexp.MustCompile(`(?:[0-9]{1,3}\.){1,4}in-addr\.arpa\b`),
	regexp.MustCompile(`(?:[0-9a-fA-F]\.){1,32}ip6\.arpa\b`),
}

// anonymizeReverseZone maps a reverse zone to the zone of the anonymized form
// of the prefix it encodes, so it follows the address rules rather than the
// domain ones: the zone of an address that is preserved is preserved too, and
// the zone of one that is replaced names the replacement. This keeps a reverse
// zone recognizable as such, and consistent with the addresses it belongs to
// elsewhere in the same output. It reports false for anything that is not a
// reverse zone.
func (a *Anonymizer) anonymizeReverseZone(domain string) (string, bool) {
	prefix, labelCount, suffix, ok := parseReverseZone(domain)
	if !ok {
		return "", false
	}

	anonymized := a.AnonymizeIP(prefix)
	if anonymized == prefix {
		return domain, true
	}

	return reverseZoneName(anonymized, labelCount) + suffix, true
}

// replaceReverseZones anonymizes every reverse zone in str and swaps each one
// for a placeholder, returning a function that puts the anonymized zones back.
// The placeholders carry no dots, digits or colons, so no later pass matches
// them.
func (a *Anonymizer) replaceReverseZones(str string) (string, func(string) string) {
	var zones []string

	for _, re := range reverseZoneRegexes {
		str = re.ReplaceAllStringFunc(str, func(match string) string {
			zone, ok := a.anonymizeReverseZone(match)
			if !ok {
				return match
			}

			zones = append(zones, zone)
			return reverseZonePlaceholder(len(zones) - 1)
		})
	}

	if len(zones) == 0 {
		return str, func(s string) string { return s }
	}

	return str, func(s string) string {
		for i, zone := range zones {
			s = strings.ReplaceAll(s, reverseZonePlaceholder(i), zone)
		}
		return s
	}
}

func reverseZonePlaceholder(index int) string {
	return "\x00reversezone" + strconv.Itoa(index) + "\x00"
}

// parseReverseZone turns a reverse zone into the address of the prefix its
// labels spell backwards, padding the absent low-order part with zeroes, and
// returns the label count and zone suffix so the name can be rebuilt.
func parseReverseZone(domain string) (netip.Addr, int, string, bool) {
	lower := strings.ToLower(domain)

	switch {
	case strings.HasSuffix(lower, reverseZoneSuffixV4):
		labels := strings.Split(strings.TrimSuffix(lower, reverseZoneSuffixV4), ".")
		addr, ok := reverseZoneAddrV4(labels)
		return addr, len(labels), reverseZoneSuffixV4, ok
	case strings.HasSuffix(lower, reverseZoneSuffixV6):
		labels := strings.Split(strings.TrimSuffix(lower, reverseZoneSuffixV6), ".")
		addr, ok := reverseZoneAddrV6(labels)
		return addr, len(labels), reverseZoneSuffixV6, ok
	default:
		return netip.Addr{}, 0, "", false
	}
}

func reverseZoneAddrV4(labels []string) (netip.Addr, bool) {
	if len(labels) == 0 || len(labels) > v4Octets {
		return netip.Addr{}, false
	}

	var octets [v4Octets]byte
	for i, label := range labels {
		octet, err := strconv.ParseUint(label, 10, 8)
		if err != nil {
			return netip.Addr{}, false
		}
		octets[len(labels)-1-i] = byte(octet)
	}

	return netip.AddrFrom4(octets), true
}

func reverseZoneAddrV6(labels []string) (netip.Addr, bool) {
	if len(labels) == 0 || len(labels) > v6Nibbles {
		return netip.Addr{}, false
	}

	nibbles := make([]byte, 0, v6Nibbles)
	for i := len(labels) - 1; i >= 0; i-- {
		if len(labels[i]) != 1 || !isHexDigit(labels[i][0]) {
			return netip.Addr{}, false
		}
		nibbles = append(nibbles, labels[i][0])
	}
	for len(nibbles) < v6Nibbles {
		nibbles = append(nibbles, '0')
	}

	var groups []string
	for i := 0; i < len(nibbles); i += 4 {
		groups = append(groups, string(nibbles[i:i+4]))
	}

	addr, err := netip.ParseAddr(strings.Join(groups, ":"))
	if err != nil {
		return netip.Addr{}, false
	}

	return addr, true
}

// reverseZoneName spells the first labelCount labels of addr backwards, the
// inverse of parseReverseZone, without the zone suffix.
func reverseZoneName(addr netip.Addr, labelCount int) string {
	labels := make([]string, 0, labelCount)

	if addr.Is4() {
		octets := addr.As4()
		for i := labelCount - 1; i >= 0; i-- {
			labels = append(labels, strconv.Itoa(int(octets[i])))
		}
		return strings.Join(labels, ".")
	}

	address := addr.As16()
	nibbles := hex.EncodeToString(address[:])
	for i := labelCount - 1; i >= 0; i-- {
		labels = append(labels, string(nibbles[i]))
	}

	return strings.Join(labels, ".")
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
