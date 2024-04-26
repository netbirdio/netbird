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

type Anonymizer struct {
	ipAnonymizer     map[netip.Addr]netip.Addr
	domainAnonymizer map[string]string
	currentAnonIPv4  netip.Addr
	currentAnonIPv6  netip.Addr
	startAnonIPv4    netip.Addr
	startAnonIPv6    netip.Addr
}

func DefaultAddresses() (netip.Addr, netip.Addr) {
	// 192.51.100.0, 100::
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
	if strings.HasSuffix(domain, "netbird.io") ||
		strings.HasSuffix(domain, "netbird.selfhosted") ||
		strings.HasSuffix(domain, "netbird.cloud") ||
		strings.HasSuffix(domain, "netbird.stage") ||
		strings.HasSuffix(domain, ".domain") {
		return domain
	}

	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return domain
	}

	baseDomain := parts[len(parts)-2] + "." + parts[len(parts)-1]

	anonymized, ok := a.domainAnonymizer[baseDomain]
	if !ok {
		anonymizedBase := "anon-" + generateRandomString(5) + ".domain"
		a.domainAnonymizer[baseDomain] = anonymizedBase
		anonymized = anonymizedBase
	}

	return strings.Replace(domain, baseDomain, anonymized, 1)
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

// AnonymizeSchemeURI finds and anonymizes URIs with stun, stuns, turn, and turns schemes.
func (a *Anonymizer) AnonymizeSchemeURI(text string) string {
	re := regexp.MustCompile(`(?i)\b(stuns?:|turns?:|https?://)\S+\b`)

	return re.ReplaceAllStringFunc(text, a.AnonymizeURI)
}

// AnonymizeDNSLogLine anonymizes domain names in DNS log entries by replacing them with a random string.
func (a *Anonymizer) AnonymizeDNSLogLine(logEntry string) string {
	domainPattern := `dns\.Question{Name:"([^"]+)",`
	domainRegex := regexp.MustCompile(domainPattern)

	return domainRegex.ReplaceAllStringFunc(logEntry, func(match string) string {
		parts := strings.Split(match, `"`)
		if len(parts) >= 2 {
			domain := parts[1]
			if strings.HasSuffix(domain, ".domain") {
				return match
			}
			randomDomain := generateRandomString(10) + ".domain"
			return strings.Replace(match, domain, randomDomain, 1)
		}
		return match
	})
}

func isWellKnown(addr netip.Addr) bool {
	wellKnown := []string{
		"8.8.8.8", "8.8.4.4", // Google DNS IPv4
		"2001:4860:4860::8888", "2001:4860:4860::8844", // Google DNS IPv6
		"1.1.1.1", "1.0.0.1", // Cloudflare DNS IPv4
		"2606:4700:4700::1111", "2606:4700:4700::1001", // Cloudflare DNS IPv6
		"9.9.9.9", "149.112.112.112", // Quad9 DNS IPv4
		"2620:fe::fe", "2620:fe::9", // Quad9 DNS IPv6
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
