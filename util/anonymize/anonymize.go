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
}

func DefaultAddresses() (string, string) {
	return "198.51.100.0", "100::"
}

func NewAnonymizer(startIPv4, startIPv6 string) (*Anonymizer, error) {
	ipv4, err := netip.ParseAddr(startIPv4)
	if err != nil {
		return nil, fmt.Errorf("parse IPv4 address: %w", err)
	}
	ipv6, err := netip.ParseAddr(startIPv6)
	if err != nil {
		return nil, fmt.Errorf("parse IPv6 address: %w", err)
	}

	return &Anonymizer{
		ipAnonymizer:     map[netip.Addr]netip.Addr{},
		domainAnonymizer: map[string]string{},
		currentAnonIPv4:  ipv4,
		currentAnonIPv6:  ipv6,
	}, nil
}

func (a *Anonymizer) AnonymizeIP(ip netip.Addr) netip.Addr {
	if ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsPrivate() ||
		ip.IsUnspecified() ||
		ip.IsMulticast() ||
		isWellKnown(ip) {
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

func (a *Anonymizer) AnonymizeIPString(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}

	return a.ipAnonymizer[a.AnonymizeIP(addr)].String()
}

func (a *Anonymizer) AnonymizeDomain(domain string) string {
	if strings.HasSuffix(domain, "netbird.io") ||
		strings.HasSuffix(domain, "netbird.selfhosted") ||
		strings.HasSuffix(domain, "netbird.cloud") ||
		strings.HasSuffix(domain, "netbird.stage") {
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
	if u.Opaque != "" {
		host, port, err := net.SplitHostPort(u.Opaque)
		if err == nil {
			u.Opaque = fmt.Sprintf("%s:%s", a.AnonymizeDomain(host), port)
		}
	} else if u.Host != "" {
		host, port, err := net.SplitHostPort(u.Host)
		if err == nil {
			u.Host = fmt.Sprintf("%s:%s", a.AnonymizeDomain(host), port)
		}
	}
	return u.String()
}

func (a *Anonymizer) AnonymizeError(errMsg string) string {
	ipv4Regex := regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	ipv6Regex := regexp.MustCompile(`\b(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|::(fff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))\b`)

	errMsg = ipv4Regex.ReplaceAllStringFunc(errMsg, a.AnonymizeIPString)
	errMsg = ipv6Regex.ReplaceAllStringFunc(errMsg, a.AnonymizeIPString)

	for domain, anonDomain := range a.domainAnonymizer {
		errMsg = strings.ReplaceAll(errMsg, domain, anonDomain)
	}

	return errMsg
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

	return slices.Contains(wellKnown, addr.String())
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
