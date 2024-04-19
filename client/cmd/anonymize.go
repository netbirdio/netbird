package cmd

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

func (a *Anonymizer) AnonymizeIP(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}

	if addr.IsLoopback() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsInterfaceLocalMulticast() ||
		addr.IsPrivate() ||
		addr.IsUnspecified() ||
		addr.IsMulticast() ||
		isWellKnown(addr) {
		return ip
	}

	if _, ok := a.ipAnonymizer[addr]; !ok {
		if addr.Is4() {
			a.ipAnonymizer[addr] = a.currentAnonIPv4
			a.currentAnonIPv4 = a.currentAnonIPv4.Next()
		} else {
			a.ipAnonymizer[addr] = a.currentAnonIPv6
			a.currentAnonIPv6 = a.currentAnonIPv6.Next()
		}
	}
	return a.ipAnonymizer[addr].String()
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

	errMsg = ipv4Regex.ReplaceAllStringFunc(errMsg, a.AnonymizeIP)
	errMsg = ipv6Regex.ReplaceAllStringFunc(errMsg, a.AnonymizeIP)

	for domain, anonDomain := range a.domainAnonymizer {
		errMsg = strings.ReplaceAll(errMsg, domain, anonDomain)
	}

	return errMsg
}

func (a *Anonymizer) AnonymizePeerDetail(peer *peerStateDetailOutput) {
	peer.FQDN = a.AnonymizeDomain(peer.FQDN)
	if localIP, port, err := net.SplitHostPort(peer.IceCandidateEndpoint.Local); err == nil {
		peer.IceCandidateEndpoint.Local = fmt.Sprintf("%s:%s", a.AnonymizeIP(localIP), port)
	}
	if remoteIP, port, err := net.SplitHostPort(peer.IceCandidateEndpoint.Remote); err == nil {
		peer.IceCandidateEndpoint.Remote = fmt.Sprintf("%s:%s", a.AnonymizeIP(remoteIP), port)
	}
	for i, route := range peer.Routes {
		peer.Routes[i] = a.AnonymizeIP(route)
	}

	for i, route := range peer.Routes {
		prefix, err := netip.ParsePrefix(route)
		if err == nil {
			ip := a.AnonymizeIP(prefix.Addr().String())
			peer.Routes[i] = fmt.Sprintf("%s/%d", ip, prefix.Bits())
		}
	}
}

func (a *Anonymizer) AnonymizeOverview(overview *statusOutputOverview) {
	for i, peer := range overview.Peers.Details {
		a.AnonymizePeerDetail(&peer)
		overview.Peers.Details[i] = peer
	}

	overview.ManagementState.URL = a.AnonymizeURI(overview.ManagementState.URL)
	overview.ManagementState.Error = a.AnonymizeError(overview.ManagementState.Error)
	overview.SignalState.URL = a.AnonymizeURI(overview.SignalState.URL)
	overview.SignalState.Error = a.AnonymizeError(overview.SignalState.Error)

	overview.IP = a.AnonymizeIP(overview.IP)
	for i, detail := range overview.Relays.Details {
		detail.URI = a.AnonymizeURI(detail.URI)
		detail.Error = a.AnonymizeError(detail.Error)
		overview.Relays.Details[i] = detail
	}

	for i, nsGroup := range overview.NSServerGroups {
		for j, domain := range nsGroup.Domains {
			overview.NSServerGroups[i].Domains[j] = a.AnonymizeDomain(domain)
		}
		for j, ns := range nsGroup.Servers {
			host, port, err := net.SplitHostPort(ns)
			if err == nil {
				overview.NSServerGroups[i].Servers[j] = fmt.Sprintf("%s:%s", a.AnonymizeIP(host), port)
			}
		}
	}

	for i, route := range overview.Routes {
		prefix, err := netip.ParsePrefix(route)
		if err == nil {
			ip := a.AnonymizeIP(prefix.Addr().String())
			overview.Routes[i] = fmt.Sprintf("%s/%d", ip, prefix.Bits())
		}
	}

	overview.FQDN = a.AnonymizeDomain(overview.FQDN)
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
