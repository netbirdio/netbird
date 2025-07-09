package mgmt

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	dnsconfig "github.com/netbirdio/netbird/client/internal/dns/config"
	"github.com/netbirdio/netbird/management/domain"
	mgmProto "github.com/netbirdio/netbird/management/proto"
)

// CacheEntry holds DNS records for a cached domain
type CacheEntry struct {
	ARecords    []dns.RR
	AAAARecords []dns.RR
}

// Resolver caches critical NetBird infrastructure domains
type Resolver struct {
	cache          map[domain.Domain]CacheEntry
	mutex          sync.RWMutex
}

// NewResolver creates a new management domains cache resolver.
func NewResolver() *Resolver {
	return &Resolver{
		cache:          make(map[domain.Domain]CacheEntry),
	}
}

// String returns a string representation of the resolver.
func (m *Resolver) String() string {
	return "MgmtCacheResolver"
}

// ServeDNS implements dns.Handler interface.
func (m *Resolver) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		m.continueToNext(w, r)
		return
	}

	question := r.Question[0]
	qname := strings.ToLower(strings.TrimSuffix(question.Name, "."))

	if question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA {
		m.continueToNext(w, r)
		return
	}

	m.mutex.RLock()
	domainKey := domain.Domain(qname)
	entry, found := m.cache[domainKey]
	m.mutex.RUnlock()

	if !found {
		m.continueToNext(w, r)
		return
	}

	resp := &dns.Msg{}
	resp.SetReply(r)
	resp.Authoritative = false
	resp.RecursionAvailable = true

	var records []dns.RR
	if question.Qtype == dns.TypeA {
		records = entry.ARecords
	} else if question.Qtype == dns.TypeAAAA {
		records = entry.AAAARecords
	}

	if len(records) == 0 {
		m.continueToNext(w, r)
		return
	}

	for _, rr := range records {
		rrCopy := dns.Copy(rr)
		rrCopy.Header().Name = question.Name
		resp.Answer = append(resp.Answer, rrCopy)
	}

	log.Debugf("serving %d cached records for domain=%s", len(resp.Answer), domainKey.SafeString())

	if err := w.WriteMsg(resp); err != nil {
		log.Errorf("failed to write response: %v", err)
	}
}

// MatchSubdomains always returns true as required by the interface.
func (m *Resolver) MatchSubdomains() bool {
	return true
}

// continueToNext signals the handler chain to continue to the next handler.
func (m *Resolver) continueToNext(w dns.ResponseWriter, r *dns.Msg) {
	resp := &dns.Msg{}
	resp.SetRcode(r, dns.RcodeNameError)
	resp.MsgHdr.Zero = true
	if err := w.WriteMsg(resp); err != nil {
		log.Errorf("failed to write continue signal: %v", err)
	}
}

// AddDomain manually adds a domain to cache by resolving it.
func (m *Resolver) AddDomain(ctx context.Context, d domain.Domain) error {
	log.Debugf("adding domain=%s to cache", d.SafeString())

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", d.PunycodeString())
	if err != nil {
		return fmt.Errorf("resolve domain %s: %w", d.SafeString(), err)
	}

	var aRecords, aaaaRecords []dns.RR
	for _, ip := range ips {
		if ip.Is4() {
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   d.PunycodeString() + ".",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: ip.AsSlice(),
			}
			aRecords = append(aRecords, rr)
		} else if ip.Is6() {
			rr := &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   d.PunycodeString() + ".",
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				AAAA: ip.AsSlice(),
			}
			aaaaRecords = append(aaaaRecords, rr)
		}
	}

	m.mutex.Lock()
	m.cache[d] = CacheEntry{
		ARecords:    aRecords,
		AAAARecords: aaaaRecords,
	}
	m.mutex.Unlock()

	log.Debugf("added domain=%s with %d A records and %d AAAA records",
		d.SafeString(), len(aRecords), len(aaaaRecords))

	return nil
}

// PopulateFromConfig extracts and caches domains from the client configuration.
func (m *Resolver) PopulateFromConfig(ctx context.Context, mgmtURL *url.URL) error {
	if mgmtURL != nil {
		if d, err := extractDomainFromURL(mgmtURL); err == nil {
			if err := m.AddDomain(ctx, d); err != nil {
				log.Warnf("failed to add management domain: %v", err)
			}
		}
	}

	return nil
}

// RemoveDomain removes a domain from the cache.
func (m *Resolver) RemoveDomain(d domain.Domain) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	delete(m.cache, d)
	log.Debugf("removed domain=%s from cache", d.SafeString())
	return nil
}

// PopulateFromNetbirdConfig extracts and caches domains from the netbird config.
func (m *Resolver) PopulateFromNetbirdConfig(ctx context.Context, config *mgmProto.NetbirdConfig) error {
	if config == nil {
		return nil
	}

	m.addSignalDomain(ctx, config.Signal)
	m.addRelayDomains(ctx, config.Relay)
	m.addFlowDomain(ctx, config.Flow)
	m.addStunDomains(ctx, config.Stuns)
	m.addTurnDomains(ctx, config.Turns)

	return nil
}

// addSignalDomain adds signal server domain to cache.
func (m *Resolver) addSignalDomain(ctx context.Context, signal *mgmProto.HostConfig) {
	if signal == nil || signal.Uri == "" {
		return
	}

	signalURL, err := url.Parse(signal.Uri)
	if err != nil {
		// If parsing fails, it might be a raw host:port, try adding a scheme
		signalURL, err = url.Parse("https://" + signal.Uri)
		if err != nil {
			log.Warnf("failed to parse signal URL: %v", err)
			return
		}
	}

	d, err := extractDomainFromURL(signalURL)
	if err != nil {
		log.Warnf("failed to extract signal domain: %v", err)
		return
	}

	if err := m.AddDomain(ctx, d); err != nil {
		log.Warnf("failed to add signal domain: %v", err)
	}
}

// addRelayDomains adds relay server domains to cache.
func (m *Resolver) addRelayDomains(ctx context.Context, relay *mgmProto.RelayConfig) {
	if relay == nil {
		return
	}

	for _, relayAddr := range relay.Urls {
		relayURL, err := url.Parse(relayAddr)
		if err != nil {
			log.Warnf("failed to parse relay URL %s: %v", relayAddr, err)
			continue
		}

		d, err := extractDomainFromURL(relayURL)
		if err != nil {
			log.Warnf("failed to extract relay domain from %s: %v", relayAddr, err)
			continue
		}

		if err := m.AddDomain(ctx, d); err != nil {
			log.Warnf("failed to add relay domain: %v", err)
		}
	}
}

// addFlowDomain adds traffic flow server domain to cache.
func (m *Resolver) addFlowDomain(ctx context.Context, flow *mgmProto.FlowConfig) {
	if flow == nil || flow.Url == "" {
		return
	}

	flowURL, err := url.Parse(flow.Url)
	if err != nil {
		log.Warnf("failed to parse flow URL: %v", err)
		return
	}

	d, err := extractDomainFromURL(flowURL)
	if err != nil {
		log.Warnf("failed to extract flow domain: %v", err)
		return
	}

	if err := m.AddDomain(ctx, d); err != nil {
		log.Warnf("failed to add flow domain: %v", err)
	}
}

// GetCachedDomains returns a list of all cached domains.
func (m *Resolver) GetCachedDomains() []domain.Domain {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	domains := make([]domain.Domain, 0, len(m.cache))
	for d := range m.cache {
		domains = append(domains, d)
	}
	return domains
}

// ClearCache removes all cached domains and returns them for external deregistration.
func (m *Resolver) ClearCache() []domain.Domain {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	domains := make([]domain.Domain, 0, len(m.cache))
	for d := range m.cache {
		domains = append(domains, d)
	}

	m.cache = make(map[domain.Domain]CacheEntry)
	log.Debugf("cleared %d cached domains", len(domains))

	return domains
}

// UpdateFromNetbirdConfig updates the cache intelligently by comparing current and new configurations.
// Returns domains that were removed for external deregistration.
func (m *Resolver) UpdateFromNetbirdConfig(ctx context.Context, config *mgmProto.NetbirdConfig) ([]domain.Domain, error) {
	log.Debugf("updating cache from NetbirdConfig")

	currentDomains := m.GetCachedDomains()
	newDomains := m.extractDomainsFromConfig(config)

	var removedDomains []domain.Domain
	for _, currentDomain := range currentDomains {
		found := false
		for _, newDomain := range newDomains {
			if currentDomain.SafeString() == newDomain.SafeString() {
				found = true
				break
			}
		}
		if !found {
			removedDomains = append(removedDomains, currentDomain)
		}
	}

	m.mutex.Lock()
	for _, domainToRemove := range removedDomains {
		delete(m.cache, domainToRemove)
		log.Debugf("removed domain=%s from cache", domainToRemove.SafeString())
	}
	m.mutex.Unlock()

	for _, newDomain := range newDomains {
		if err := m.AddDomain(ctx, newDomain); err != nil {
			log.Warnf("failed to add/update domain=%s: %v", newDomain.SafeString(), err)
		}
	}

	return removedDomains, nil
}

// UpdateFromServerDomains updates the cache using the simplified ServerDomains struct
func (m *Resolver) UpdateFromServerDomains(ctx context.Context, serverDomains dnsconfig.ServerDomains) ([]domain.Domain, error) {
	log.Debugf("updating cache from ServerDomains")

	currentDomains := m.GetCachedDomains()
	newDomains := m.extractDomainsFromServerDomains(serverDomains)

	var removedDomains []domain.Domain
	for _, currentDomain := range currentDomains {
		found := false
		for _, newDomain := range newDomains {
			if currentDomain.SafeString() == newDomain.SafeString() {
				found = true
				break
			}
		}
		if !found {
			removedDomains = append(removedDomains, currentDomain)
			if err := m.RemoveDomain(currentDomain); err != nil {
				log.Warnf("failed to remove domain=%s: %v", currentDomain.SafeString(), err)
			}
		}
	}

	for _, newDomain := range newDomains {
		if err := m.AddDomain(ctx, newDomain); err != nil {
			log.Warnf("failed to add/update domain=%s: %v", newDomain.SafeString(), err)
		} else {
			log.Debugf("added/updated management cache domain=%s", newDomain.SafeString())
		}
	}

	return removedDomains, nil
}

func (m *Resolver) extractDomainsFromServerDomains(serverDomains dnsconfig.ServerDomains) []domain.Domain {
	var domains []domain.Domain

	if serverDomains.Signal != "" {
		domains = append(domains, serverDomains.Signal)
	}

	for _, relay := range serverDomains.Relay {
		if relay != "" {
			domains = append(domains, relay)
		}
	}

	if serverDomains.Flow != "" {
		domains = append(domains, serverDomains.Flow)
	}

	for _, stun := range serverDomains.Stuns {
		if stun != "" {
			domains = append(domains, stun)
		}
	}

	for _, turn := range serverDomains.Turns {
		if turn != "" {
			domains = append(domains, turn)
		}
	}

	return domains
}

// extractDomainsFromConfig extracts all domains from a NetbirdConfig.
func (m *Resolver) extractDomainsFromConfig(config *mgmProto.NetbirdConfig) []domain.Domain {
	if config == nil {
		return nil
	}

	var domains []domain.Domain

	// Extract signal domain
	domains = append(domains, m.extractSignalDomain(config)...)

	// Extract relay domains
	domains = append(domains, m.extractRelayDomains(config)...)

	// Extract flow domain
	domains = append(domains, m.extractFlowDomain(config)...)

	// Extract STUN domains
	domains = append(domains, m.extractSTUNDomains(config)...)

	// Extract TURN domains
	domains = append(domains, m.extractTURNDomains(config)...)

	return domains
}

func (m *Resolver) extractSignalDomain(config *mgmProto.NetbirdConfig) []domain.Domain {
	if config.Signal == nil || config.Signal.Uri == "" {
		return nil
	}

	if d, err := m.extractDomainFromSignalConfig(config.Signal); err == nil {
		return []domain.Domain{d}
	}
	return nil
}

func (m *Resolver) extractRelayDomains(config *mgmProto.NetbirdConfig) []domain.Domain {
	if config.Relay == nil {
		return nil
	}

	var domains []domain.Domain
	for _, relayURL := range config.Relay.Urls {
		if d, err := m.extractDomainFromURL(relayURL); err == nil {
			domains = append(domains, d)
		}
	}
	return domains
}

func (m *Resolver) extractFlowDomain(config *mgmProto.NetbirdConfig) []domain.Domain {
	if config.Flow == nil || config.Flow.Url == "" {
		return nil
	}

	if d, err := m.extractDomainFromURL(config.Flow.Url); err == nil {
		return []domain.Domain{d}
	}
	return nil
}

func (m *Resolver) extractSTUNDomains(config *mgmProto.NetbirdConfig) []domain.Domain {
	var domains []domain.Domain
	for _, stun := range config.Stuns {
		if stun != nil && stun.Uri != "" {
			if d, err := m.extractDomainFromURL(stun.Uri); err == nil {
				domains = append(domains, d)
			}
		}
	}
	return domains
}

func (m *Resolver) extractTURNDomains(config *mgmProto.NetbirdConfig) []domain.Domain {
	var domains []domain.Domain
	for _, turn := range config.Turns {
		if turn != nil && turn.HostConfig != nil && turn.HostConfig.Uri != "" {
			if d, err := m.extractDomainFromURL(turn.HostConfig.Uri); err == nil {
				domains = append(domains, d)
			}
		}
	}
	return domains
}

// extractDomainFromSignalConfig extracts domain from signal configuration.
func (m *Resolver) extractDomainFromSignalConfig(signal *mgmProto.HostConfig) (domain.Domain, error) {
	signalURL, err := url.Parse(signal.Uri)
	if err != nil {
		// If parsing fails, it might be a raw host:port, try adding a scheme
		signalURL, err = url.Parse("https://" + signal.Uri)
		if err != nil {
			return "", err
		}
	}
	return extractDomainFromURL(signalURL)
}

// extractDomainFromURL extracts domain from a URL string.
func (m *Resolver) extractDomainFromURL(urlStr string) (domain.Domain, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}
	return extractDomainFromURL(parsedURL)
}

// addStunDomains adds STUN server domains to cache.
func (m *Resolver) addStunDomains(ctx context.Context, stuns []*mgmProto.HostConfig) {
	for _, stun := range stuns {
		if stun == nil || stun.Uri == "" {
			continue
		}

		stunURL, err := url.Parse(stun.Uri)
		if err != nil {
			log.Warnf("failed to parse STUN URL %s: %v", stun.Uri, err)
			continue
		}

		d, err := extractDomainFromURL(stunURL)
		if err != nil {
			log.Warnf("failed to extract STUN domain from %s: %v", stun.Uri, err)
			continue
		}

		if err := m.AddDomain(ctx, d); err != nil {
			log.Warnf("failed to add STUN domain: %v", err)
		}
	}
}

// addTurnDomains adds TURN server domains to cache.
func (m *Resolver) addTurnDomains(ctx context.Context, turns []*mgmProto.ProtectedHostConfig) {
	for _, turn := range turns {
		if turn == nil || turn.HostConfig == nil || turn.HostConfig.Uri == "" {
			continue
		}

		turnURL, err := url.Parse(turn.HostConfig.Uri)
		if err != nil {
			log.Warnf("failed to parse TURN URL %s: %v", turn.HostConfig.Uri, err)
			continue
		}

		d, err := extractDomainFromURL(turnURL)
		if err != nil {
			log.Warnf("failed to extract TURN domain from %s: %v", turn.HostConfig.Uri, err)
			continue
		}

		if err := m.AddDomain(ctx, d); err != nil {
			log.Warnf("failed to add TURN domain: %v", err)
		}
	}
}

// extractDomainFromURL extracts the domain from a URL.
func extractDomainFromURL(u *url.URL) (domain.Domain, error) {
	if u == nil {
		return "", errors.New("invalid URL")
	}

	host := u.Host
	// If Host is empty, try to extract from Opaque (for schemes like stun:domain:port)
	if host == "" && u.Opaque != "" {
		host = u.Opaque
	}
	if host == "" && u.Path != "" {
		host = strings.TrimPrefix(u.Path, "/")
	}

	if host == "" {
		return "", errors.New("empty host")
	}

	host, _, err := net.SplitHostPort(host)
	if err != nil {
		switch {
		case u.Host != "":
			host = u.Host
		case u.Opaque != "":
			host = u.Opaque
		default:
			host = strings.TrimPrefix(u.Path, "/")
		}
	}

	if _, err := netip.ParseAddr(host); err == nil {
		return "", errors.New("host is an IP address, skipping")
	}

	return domain.FromString(host)
}
