package anonymize

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

const anonTLD = ".domain"

type Anonymizer struct {
	ipAnonymizer     map[netip.Addr]netip.Addr
	domainAnonymizer map[string]string
	currentAnonIPv4  netip.Addr
	currentAnonIPv6  netip.Addr
	startAnonIPv4    netip.Addr
	startAnonIPv6    netip.Addr

	domainKeyRegex *regexp.Regexp
}

func DefaultAddresses() (netip.Addr, netip.Addr) {
	// 198.51.100.0, 100::
	return netip.AddrFrom4([4]byte{198, 51, 100, 0}), netip.AddrFrom16([16]byte{0x01})
}

func NewAnonymizer(startIPv4, startIPv6 netip.Addr) *Anonymizer {
	return &Anonymizer{
		ipAnonymizer:     map[netip.Addr]netip.Addr{},
		domainAnonymizer: map[string]string{},
		currentAnonIPv4:  startIPv4,
		currentAnonIPv6:  startIPv6,
		startAnonIPv4:    startIPv4,
		startAnonIPv6:    startIPv6,

		domainKeyRegex: regexp.MustCompile(`\bdomain=([^\s,:"]+)`),
	}
}

func (a *Anonymizer) AnonymizeIP(ip netip.Addr) netip.Addr {
	if ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsPrivate() ||
		ip.IsUnspecified() ||
		ip.IsMulticast() ||
		isWellKnown(ip) ||
		a.isInAnonymizedRange(ip) {

		return ip
	}

	if _, ok := a.ipAnonymizer[ip]; !ok {
		if ip.Is4() {
			a.ipAnonymizer[ip] = a.currentAnonIPv4
			a.currentAnonIPv4 = a.currentAnonIPv4.Next()
		} else {
			a.ipAnonymizer[ip] = a.currentAnonIPv6
			a.currentAnonIPv6 = a.currentAnonIPv6.Next()
		}
	}
	return a.ipAnonymizer[ip]
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
	if ip.Is4() && ip.Compare(a.startAnonIPv4) >= 0 && ip.Compare(a.currentAnonIPv4) <= 0 {
		return true
	} else if !ip.Is4() && ip.Compare(a.startAnonIPv6) >= 0 && ip.Compare(a.currentAnonIPv6) <= 0 {
		return true
	}
	return false
}

func (a *Anonymizer) AnonymizeIPString(ip string) string {
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

	if strings.HasSuffix(baseDomain, "netbird.io") ||
		strings.HasSuffix(baseDomain, "netbird.selfhosted") ||
		strings.HasSuffix(baseDomain, "netbird.cloud") ||
		strings.HasSuffix(baseDomain, "netbird.stage") ||
		strings.HasSuffix(baseDomain, anonTLD) {
		return domain
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
	if hasDot {
		result += "."
	}
	return result
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
			anonymizedHost = fmt.Sprintf("%s:%s", a.AnonymizeDomain(host), port)
		} else {
			anonymizedHost = a.AnonymizeDomain(u.Opaque)
		}
		u.Opaque = anonymizedHost
	} else if u.Host != "" {
		host, port, err := net.SplitHostPort(u.Host)
		if err == nil {
			anonymizedHost = fmt.Sprintf("%s:%s", a.AnonymizeDomain(host), port)
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

	str = ipv4Regex.ReplaceAllStringFunc(str, a.AnonymizeIPString)
	str = ipv6Regex.ReplaceAllStringFunc(str, a.AnonymizeIPString)

	for domain, anonDomain := range a.domainAnonymizer {
		str = strings.ReplaceAll(str, domain, anonDomain)
	}

	str = a.AnonymizeSchemeURI(str)
	str = a.AnonymizeDNSLogLine(str)

	return str
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

	if slices.Contains(wellKnown, addr.String()) {
		return true
	}

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
