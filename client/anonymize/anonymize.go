package anonymize

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const anonTLD = ".domain"

// Level selects how much the anonymizer redacts. Levels are ordered: a higher
// level redacts strictly more. On the wire (protos, flags) levels travel as
// their string form.
type Level int

const (
	// LevelDefault anonymizes public IP addresses, IPv6 ULA, domains, and MAC
	// addresses. Internal IPv4 ranges (RFC 1918, CGNAT, link-local) are
	// preserved so support can reason about the real topology.
	LevelDefault Level = iota
	// LevelStrict additionally anonymizes internal IP ranges, peer names, and
	// WireGuard public keys.
	LevelStrict
)

// LevelDefaultString and LevelStrictString are the wire forms of the levels,
// for boundaries that pass levels as strings (flags, protos, mobile bindings).
const (
	LevelDefaultString = "default"
	LevelStrictString  = "strict"
)

// ParseLevel maps s to a Level. Empty means LevelDefault; anything
// unrecognized maps to LevelStrict so an unknown request never yields less
// anonymization than intended.
func ParseLevel(s string) Level {
	switch strings.ToLower(s) {
	case "", LevelDefaultString:
		return LevelDefault
	default:
		return LevelStrict
	}
}

// String returns the wire form of the level: "default" or "strict".
func (l Level) String() string {
	if l >= LevelStrict {
		return LevelStrictString
	}
	return LevelDefaultString
}

// protectedDomains are NetBird-operated suffixes that stay recognizable in an
// anonymized bundle. At LevelStrict the labels in front of them (the peer
// name) are still replaced, except under netbird.io, which only hosts
// NetBird infrastructure (api, signal, flow), never peer names.
var protectedDomains = []string{"netbird.io", "netbird.selfhosted", "netbird.cloud", "netbird.stage"}

const infraDomain = "netbird.io"

var (
	macColonRegex = regexp.MustCompile(`\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b`)
	macDashRegex  = regexp.MustCompile(`\b[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5}\b`)
	wgKeyRegex    = regexp.MustCompile(`\b[A-Za-z0-9+/]{43}=`)
)

type Anonymizer struct {
	ipAnonymizer     map[netip.Addr]netip.Addr
	domainAnonymizer map[string]string
	// domainOrder caches the keys of domainAnonymizer sorted longest-first
	// for AnonymizeString; it is rebuilt when the map gains entries.
	domainOrder     []string
	labelAnonymizer map[string]string
	labelAnonymized map[string]struct{}
	labelCounter    uint32
	macAnonymizer   map[string]string
	macCounter      uint32
	wgKeyAnonymizer map[string]string
	wgKeyAnonymized map[string]struct{}
	currentAnonIPv4 netip.Addr
	currentAnonIPv6 netip.Addr
	startAnonIPv4   netip.Addr
	startAnonIPv6   netip.Addr

	// LevelStrict also anonymizes internal ranges (RFC 1918, CGNAT,
	// link-local), replacing them from the dedicated internal pools below so
	// a reader can still tell an internal address from a public one.
	level                   Level
	currentAnonInternalIPv4 netip.Addr
	currentAnonInternalIPv6 netip.Addr
	startAnonInternalIPv4   netip.Addr
	startAnonInternalIPv6   netip.Addr

	domainKeyRegex *regexp.Regexp
}

func DefaultAddresses() (netip.Addr, netip.Addr) {
	// 198.51.100.0 (RFC 5737 TEST-NET-2), 2001:db8:ffff:: (RFC 3849 documentation, last /48)
	// The old start 100:: (discard, RFC 6666) is now used for fake IPs on Android.
	return netip.AddrFrom4([4]byte{198, 51, 100, 0}), netip.MustParseAddr("2001:db8:ffff::")
}

// InternalAddresses returns the pool starts used in strict mode for internal
// ranges. Both are reserved ranges that cannot collide with real addressing:
// 198.18.0.0 (RFC 2544 benchmarking), 2001:db8:1:: (RFC 3849 documentation).
func InternalAddresses() (netip.Addr, netip.Addr) {
	return netip.AddrFrom4([4]byte{198, 18, 0, 0}), netip.MustParseAddr("2001:db8:1::")
}

func NewAnonymizer(startIPv4, startIPv6 netip.Addr) *Anonymizer {
	internalIPv4, internalIPv6 := InternalAddresses()
	return &Anonymizer{
		ipAnonymizer:     map[netip.Addr]netip.Addr{},
		domainAnonymizer: map[string]string{},
		labelAnonymizer:  map[string]string{},
		labelAnonymized:  map[string]struct{}{},
		macAnonymizer:    map[string]string{},
		wgKeyAnonymizer:  map[string]string{},
		wgKeyAnonymized:  map[string]struct{}{},
		currentAnonIPv4:  startIPv4,
		currentAnonIPv6:  startIPv6,
		startAnonIPv4:    startIPv4,
		startAnonIPv6:    startIPv6,

		level:                   LevelDefault,
		currentAnonInternalIPv4: internalIPv4,
		currentAnonInternalIPv6: internalIPv6,
		startAnonInternalIPv4:   internalIPv4,
		startAnonInternalIPv6:   internalIPv6,

		domainKeyRegex: regexp.MustCompile(`\bdomain=([^\s,:"]+)`),
	}
}

// SetLevel selects the anonymization level. The zero value of a new
// Anonymizer is LevelDefault.
func (a *Anonymizer) SetLevel(level Level) {
	a.level = level
}

func (a *Anonymizer) AnonymizeIP(ip netip.Addr) netip.Addr {
	// Normalize 4-in-6 addresses so ::ffff:192.168.1.1 classifies and maps
	// like 192.168.1.1.
	ip = ip.Unmap()

	if ip.IsLoopback() ||
		ip.IsUnspecified() ||
		ip.IsMulticast() ||
		isWellKnown(ip) ||
		a.isInAnonymizedRange(ip) {

		return ip
	}

	if isInternal(ip) && a.level < LevelStrict {
		return ip
	}

	if _, ok := a.ipAnonymizer[ip]; !ok {
		a.ipAnonymizer[ip] = a.nextAnonIP(ip)
	}
	return a.ipAnonymizer[ip]
}

func (a *Anonymizer) nextAnonIP(ip netip.Addr) netip.Addr {
	// At the strict level, internal addresses (including IPv6 ULA, matched
	// by IsPrivate) come from the internal pools so they remain recognizable
	// as internal without disclosing the real values.
	if a.level >= LevelStrict && (isInternal(ip) || ip.IsPrivate()) {
		if ip.Is4() {
			anon := a.currentAnonInternalIPv4
			a.currentAnonInternalIPv4 = a.currentAnonInternalIPv4.Next()
			return anon
		}
		anon := a.currentAnonInternalIPv6
		a.currentAnonInternalIPv6 = a.currentAnonInternalIPv6.Next()
		return anon
	}

	if ip.Is4() {
		anon := a.currentAnonIPv4
		a.currentAnonIPv4 = a.currentAnonIPv4.Next()
		return anon
	}
	anon := a.currentAnonIPv6
	a.currentAnonIPv6 = a.currentAnonIPv6.Next()
	return anon
}

// AnonymizeMAC replaces a MAC address with a consistent placeholder from the
// locally administered range starting at 02:00:00:00:00:01, at every
// anonymization level. Broadcast, multicast, all-zero, and already assigned
// placeholder addresses are preserved. The colon and dash spellings of the
// same address share one placeholder; the output keeps the input's separator.
func (a *Anonymizer) AnonymizeMAC(mac string) string {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return mac
	}

	if isWellKnownMAC(hw) || a.isAnonymizedMAC(hw) {
		return mac
	}

	key := hw.String()
	anon, ok := a.macAnonymizer[key]
	if !ok {
		a.macCounter++
		anon = fmt.Sprintf("02:00:00:%02x:%02x:%02x", byte(a.macCounter>>16), byte(a.macCounter>>8), byte(a.macCounter))
		a.macAnonymizer[key] = anon
	}

	if strings.Contains(mac, "-") {
		anon = strings.ReplaceAll(anon, ":", "-")
	}
	return anon
}

// isAnonymizedMAC reports whether hw is a placeholder this anonymizer already
// handed out, so a second pass over anonymized output leaves it unchanged.
func (a *Anonymizer) isAnonymizedMAC(hw net.HardwareAddr) bool {
	if hw[0] != 0x02 || hw[1] != 0 || hw[2] != 0 {
		return false
	}
	value := uint32(hw[3])<<16 | uint32(hw[4])<<8 | uint32(hw[5])
	return value <= a.macCounter
}

// AnonymizeWGKey replaces a WireGuard public key with a consistent random
// placeholder of the same shape. Keys are only anonymized at LevelStrict;
// placeholders already handed out pass through unchanged.
func (a *Anonymizer) AnonymizeWGKey(key string) string {
	if a.level < LevelStrict || !looksLikeWGKey(key) {
		return key
	}
	if _, ok := a.wgKeyAnonymized[key]; ok {
		return key
	}

	anon, ok := a.wgKeyAnonymizer[key]
	if !ok {
		anon = generateAnonymousKey()
		a.wgKeyAnonymizer[key] = anon
		a.wgKeyAnonymized[anon] = struct{}{}
	}
	return anon
}

func (a *Anonymizer) AnonymizeUDPAddr(addr net.UDPAddr) net.UDPAddr {
	// Convert IP to netip.Addr
	ip, ok := netip.AddrFromSlice(addr.IP)
	if !ok {
		return addr
	}

	anonIP := a.AnonymizeIP(ip)

	return net.UDPAddr{
		IP:   anonIP.AsSlice(),
		Port: addr.Port,
		Zone: addr.Zone,
	}
}

// isInAnonymizedRange checks if an IP is within the range of already assigned anonymized IPs
func (a *Anonymizer) isInAnonymizedRange(ip netip.Addr) bool {
	if ip.Is4() {
		return inPoolRange(ip, a.startAnonIPv4, a.currentAnonIPv4) ||
			inPoolRange(ip, a.startAnonInternalIPv4, a.currentAnonInternalIPv4)
	}
	return inPoolRange(ip, a.startAnonIPv6, a.currentAnonIPv6) ||
		inPoolRange(ip, a.startAnonInternalIPv6, a.currentAnonInternalIPv6)
}

func (a *Anonymizer) AnonymizeIPString(ip string) string {
	// Handle CIDR notation (e.g. "2001:db8::/32")
	if prefix, err := netip.ParsePrefix(ip); err == nil {
		return a.AnonymizeIP(prefix.Addr()).String() + "/" + strconv.Itoa(prefix.Bits())
	}

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}

	return a.AnonymizeIP(addr).String()
}

func (a *Anonymizer) AnonymizeDomain(domain string) string {
	baseDomain := domain
	hasDot := strings.HasSuffix(domain, ".")
	if hasDot {
		baseDomain = domain[:len(domain)-1]
	}

	if strings.HasSuffix(baseDomain, anonTLD) {
		return domain
	}

	// A reverse zone names an address prefix, so it follows the address rules,
	// which also keeps its digit labels intact.
	if zone, ok := a.anonymizeReverseZone(baseDomain); ok {
		return withTrailingDot(zone, hasDot)
	}

	if suffix := protectedSuffix(baseDomain); suffix != "" {
		if a.level < LevelStrict || baseDomain == suffix || suffix == infraDomain {
			return domain
		}
		return withTrailingDot(a.anonymizePeerName(baseDomain, suffix), hasDot)
	}

	parts := strings.Split(baseDomain, ".")
	if len(parts) < 2 {
		return domain
	}

	baseForLookup := parts[len(parts)-2] + "." + parts[len(parts)-1]

	anonymized, ok := a.domainAnonymizer[baseForLookup]
	if !ok {
		anonymizedBase := "anon-" + generateRandomString(5) + anonTLD
		a.domainAnonymizer[baseForLookup] = anonymizedBase
		anonymized = anonymizedBase
	}

	result := strings.Replace(baseDomain, baseForLookup, anonymized, 1)
	if a.level >= LevelStrict && len(parts) > 2 {
		prefix := strings.TrimSuffix(baseDomain, "."+baseForLookup)
		result = a.anonymizeLabels(prefix, "host") + "." + anonymized
		// The full mapping feeds AnonymizeString so seeded FQDNs are caught
		// in log lines as a whole, labels included.
		a.domainAnonymizer[baseDomain] = result
	}
	return withTrailingDot(result, hasDot)
}

// anonymizePeerName replaces the labels in front of a protected suffix with
// numbered peer placeholders, keeping the suffix, and records the full
// mapping for string replacement in logs. The numbering keeps a peer
// recognizable across the whole bundle without disclosing its name.
func (a *Anonymizer) anonymizePeerName(baseDomain, suffix string) string {
	prefix := strings.TrimSuffix(baseDomain, "."+suffix)
	result := a.anonymizeLabels(prefix, "peer") + "." + suffix
	if result != baseDomain {
		a.domainAnonymizer[baseDomain] = result
	}
	return result
}

// anonymizeLabels replaces each dot-separated label with a consistent
// numbered placeholder ("<placeholder>-<n>"). Wildcard labels and
// placeholders already handed out pass through unchanged.
func (a *Anonymizer) anonymizeLabels(prefix, placeholder string) string {
	labels := strings.Split(prefix, ".")
	for i, label := range labels {
		if label == "*" {
			continue
		}
		if _, ok := a.labelAnonymized[label]; ok {
			continue
		}
		anon, ok := a.labelAnonymizer[label]
		if !ok {
			a.labelCounter++
			anon = fmt.Sprintf("%s-%d", placeholder, a.labelCounter)
			a.labelAnonymizer[label] = anon
			a.labelAnonymized[anon] = struct{}{}
		}
		labels[i] = anon
	}
	return strings.Join(labels, ".")
}

func (a *Anonymizer) AnonymizeURI(uri string) string {
	u, err := url.Parse(uri)
	if err != nil {
		return uri
	}

	var anonymizedHost string
	if u.Opaque != "" {
		host, port, err := net.SplitHostPort(u.Opaque)
		if err == nil {
			anonymizedHost = net.JoinHostPort(a.AnonymizeDomain(host), port)
		} else {
			anonymizedHost = a.AnonymizeDomain(u.Opaque)
		}
		u.Opaque = anonymizedHost
	} else if u.Host != "" {
		host, port, err := net.SplitHostPort(u.Host)
		if err == nil {
			anonymizedHost = net.JoinHostPort(a.AnonymizeDomain(host), port)
		} else {
			anonymizedHost = a.AnonymizeDomain(u.Host)
		}
		u.Host = anonymizedHost
	}
	return u.String()
}

func (a *Anonymizer) AnonymizeString(str string) string {
	ipv4Regex := regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	ipv6Regex := regexp.MustCompile(`\b([0-9a-fA-F:]+:+[0-9a-fA-F]{0,4})(?:%[0-9a-zA-Z]+)?(?:\/[0-9]{1,3})?(?::[0-9]{1,5})?\b`)

	// Reverse zones go first and are then held out of the passes below: their
	// labels are digits, which the address patterns would otherwise consume.
	str, restoreZones := a.replaceReverseZones(str)

	str = ipv4Regex.ReplaceAllStringFunc(str, a.AnonymizeIPString)
	str = ipv6Regex.ReplaceAllStringFunc(str, a.AnonymizeIPString)

	for _, domain := range a.sortedDomains() {
		str = strings.ReplaceAll(str, domain, a.domainAnonymizer[domain])
	}

	str = a.AnonymizeSchemeURI(str)
	str = a.AnonymizeDNSLogLine(str)

	// MAC handling runs after the IP passes so preserved IPv6 addresses are
	// already out of the way; the separator guard skips matches embedded in a
	// longer colon- or dash-separated sequence (such as an IPv6 tail).
	str = a.anonymizeMACsInString(str, macColonRegex, ':')
	str = a.anonymizeMACsInString(str, macDashRegex, '-')

	if a.level >= LevelStrict {
		str = wgKeyRegex.ReplaceAllStringFunc(str, a.AnonymizeWGKey)
	}

	return restoreZones(str)
}

// sortedDomains returns the domain mappings longest-first, so a full-FQDN
// mapping (strict level) is applied before the base-domain mapping it
// contains. The order is rebuilt only when domainAnonymizer has grown.
func (a *Anonymizer) sortedDomains() []string {
	if len(a.domainOrder) == len(a.domainAnonymizer) {
		return a.domainOrder
	}

	a.domainOrder = a.domainOrder[:0]
	for domain := range a.domainAnonymizer {
		a.domainOrder = append(a.domainOrder, domain)
	}
	slices.SortFunc(a.domainOrder, func(x, y string) int {
		if d := len(y) - len(x); d != 0 {
			return d
		}
		return strings.Compare(x, y)
	})
	return a.domainOrder
}

// anonymizeMACsInString replaces MAC addresses matched by re, skipping
// matches that directly adjoin another sep so a six-group run inside a longer
// separated sequence is left alone.
func (a *Anonymizer) anonymizeMACsInString(str string, re *regexp.Regexp, sep byte) string {
	matches := re.FindAllStringIndex(str, -1)
	if len(matches) == 0 {
		return str
	}

	var b strings.Builder
	last := 0
	for _, m := range matches {
		if (m[0] > 0 && str[m[0]-1] == sep) || (m[1] < len(str) && str[m[1]] == sep) {
			continue
		}
		b.WriteString(str[last:m[0]])
		b.WriteString(a.AnonymizeMAC(str[m[0]:m[1]]))
		last = m[1]
	}
	b.WriteString(str[last:])
	return b.String()
}

// AnonymizeSchemeURI finds and anonymizes URIs with ws, wss, rel, rels, stun, stuns, turn, and turns schemes.
func (a *Anonymizer) AnonymizeSchemeURI(text string) string {
	re := regexp.MustCompile(`(?i)\b(wss?://|rels?://|stuns?:|turns?:|https?://)\S+\b`)

	return re.ReplaceAllStringFunc(text, a.AnonymizeURI)
}

func (a *Anonymizer) AnonymizeDNSLogLine(logEntry string) string {
	return a.domainKeyRegex.ReplaceAllStringFunc(logEntry, func(match string) string {
		parts := strings.SplitN(match, "=", 2)
		if len(parts) >= 2 {
			domain := parts[1]
			if strings.HasSuffix(domain, anonTLD) {
				return match
			}
			return "domain=" + a.AnonymizeDomain(domain)
		}
		return match
	})
}

// AnonymizeRoute anonymizes a route string by replacing IP addresses with anonymized versions and
// domain names with random strings.
func (a *Anonymizer) AnonymizeRoute(route string) string {
	prefix, err := netip.ParsePrefix(route)
	if err == nil {
		ip := a.AnonymizeIPString(prefix.Addr().String())
		return fmt.Sprintf("%s/%d", ip, prefix.Bits())
	}
	domains := strings.Split(route, ", ")
	for i, domain := range domains {
		domains[i] = a.AnonymizeDomain(domain)
	}
	return strings.Join(domains, ", ")
}

func isWellKnown(addr netip.Addr) bool {
	wellKnown := []string{
		"8.8.8.8", "8.8.4.4", // Google DNS IPv4
		"2001:4860:4860::8888", "2001:4860:4860::8844", // Google DNS IPv6
		"1.1.1.1", "1.0.0.1", // Cloudflare DNS IPv4
		"2606:4700:4700::1111", "2606:4700:4700::1001", // Cloudflare DNS IPv6
		"9.9.9.9", "149.112.112.112", // Quad9 DNS IPv4
		"2620:fe::fe", "2620:fe::9", // Quad9 DNS IPv6

		"128.0.0.0", "8000::", // 2nd split subnet for default routes
	}

	return slices.Contains(wellKnown, addr.String())
}

// isInternal reports whether ip identifies a host only within the local
// network: IPv4 private (RFC 1918), CGNAT (RFC 6598), and link-local (v4 and
// v6). These are preserved at the default level so support can reason about
// the real topology, and replaced from the internal pools at the strict
// level. IPv6 ULA is deliberately not internal: its random global ID uniquely
// fingerprints the network, so it is anonymized at every level.
func isInternal(ip netip.Addr) bool {
	return (ip.Is4() && ip.IsPrivate()) ||
		ip.IsLinkLocalUnicast() ||
		isCGNAT(ip)
}

func inPoolRange(ip, start, current netip.Addr) bool {
	return ip.Compare(start) >= 0 && ip.Compare(current) <= 0
}

// isWellKnownMAC reports whether hw carries no stable host identity: all-zero
// or a group address (broadcast and multicast).
func isWellKnownMAC(hw net.HardwareAddr) bool {
	if hw[0]&1 == 1 {
		return true
	}
	for _, b := range hw {
		if b != 0 {
			return false
		}
	}
	return true
}

// looksLikeWGKey reports whether s has the shape of a WireGuard key:
// 44 base64 characters decoding to 32 bytes.
func looksLikeWGKey(s string) bool {
	if len(s) != 44 || s[43] != '=' {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(decoded) == 32
}

func generateAnonymousKey() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return strings.Repeat("A", 43) + "="
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// protectedSuffix returns the protected NetBird suffix baseDomain ends with,
// or empty. The match is label-anchored so an unrelated domain that merely
// ends in the same characters is not preserved.
func protectedSuffix(baseDomain string) string {
	for _, d := range protectedDomains {
		if baseDomain == d || strings.HasSuffix(baseDomain, "."+d) {
			return d
		}
	}
	return ""
}

func withTrailingDot(domain string, hasDot bool) string {
	if hasDot {
		return domain + "."
	}
	return domain
}

// isCGNAT reports whether addr is in 100.64.0.0/10 (RFC 6598), the range
// NetBird assigns overlay peer addresses from.
func isCGNAT(addr netip.Addr) bool {
	cgnatRangeStart := netip.AddrFrom4([4]byte{100, 64, 0, 0})
	cgnatRange := netip.PrefixFrom(cgnatRangeStart, 10)

	return cgnatRange.Contains(addr)
}

func generateRandomString(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			continue
		}
		result[i] = letters[num.Int64()]
	}
	return string(result)
}
