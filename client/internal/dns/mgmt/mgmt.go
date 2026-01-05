package mgmt

import (
	"context"
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
	"github.com/netbirdio/netbird/shared/management/domain"
)

const dnsTimeout = 5 * time.Second

// Resolver caches critical NetBird infrastructure domains
type Resolver struct {
	records       map[dns.Question][]dns.RR
	mgmtDomain    *domain.Domain
	serverDomains *dnsconfig.ServerDomains
	mutex         sync.RWMutex
}

type ipsResponse struct {
	ips []netip.Addr
	err error
}

// NewResolver creates a new management domains cache resolver.
func NewResolver() *Resolver {
	return &Resolver{
		records: make(map[dns.Question][]dns.RR),
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
	question.Name = strings.ToLower(dns.Fqdn(question.Name))

	if question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA {
		m.continueToNext(w, r)
		return
	}

	m.mutex.RLock()
	records, found := m.records[question]
	m.mutex.RUnlock()

	if !found {
		m.continueToNext(w, r)
		return
	}

	resp := &dns.Msg{}
	resp.SetReply(r)
	resp.Authoritative = false
	resp.RecursionAvailable = true

	resp.Answer = append(resp.Answer, records...)

	log.Debugf("serving %d cached records for domain=%s", len(resp.Answer), question.Name)

	if err := w.WriteMsg(resp); err != nil {
		log.Errorf("failed to write response: %v", err)
	}
}

// MatchSubdomains returns false since this resolver only handles exact domain matches
// for NetBird infrastructure domains (signal, relay, flow, etc.), not their subdomains.
func (m *Resolver) MatchSubdomains() bool {
	return false
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
	dnsName := strings.ToLower(dns.Fqdn(d.PunycodeString()))

	ctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()

	ips, err := lookupIPWithExtraTimeout(ctx, d)
	if err != nil {
		return err
	}

	var aRecords, aaaaRecords []dns.RR
	for _, ip := range ips {
		if ip.Is4() {
			rr := &dns.A{
				Hdr: dns.RR_Header{
					Name:   dnsName,
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
					Name:   dnsName,
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

	if len(aRecords) > 0 {
		aQuestion := dns.Question{
			Name:   dnsName,
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}
		m.records[aQuestion] = aRecords
	}

	if len(aaaaRecords) > 0 {
		aaaaQuestion := dns.Question{
			Name:   dnsName,
			Qtype:  dns.TypeAAAA,
			Qclass: dns.ClassINET,
		}
		m.records[aaaaQuestion] = aaaaRecords
	}

	m.mutex.Unlock()

	log.Debugf("added domain=%s with %d A records and %d AAAA records",
		d.SafeString(), len(aRecords), len(aaaaRecords))

	return nil
}

func lookupIPWithExtraTimeout(ctx context.Context, d domain.Domain) ([]netip.Addr, error) {
	log.Infof("looking up IP for mgmt domain=%s", d.SafeString())
	defer log.Infof("done looking up IP for mgmt domain=%s", d.SafeString())
	resultChan := make(chan *ipsResponse, 1)

	go func() {
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", d.PunycodeString())
		resultChan <- &ipsResponse{
			err: err,
			ips: ips,
		}
	}()

	var resp *ipsResponse

	select {
	case <-time.After(dnsTimeout + time.Millisecond*500):
		log.Warnf("timed out waiting for IP for mgmt domain=%s", d.SafeString())
		return nil, fmt.Errorf("timed out waiting for ips to be available for domain %s", d.SafeString())
	case <-ctx.Done():
		return nil, ctx.Err()
	case resp = <-resultChan:
	}

	if resp.err != nil {
		return nil, fmt.Errorf("resolve domain %s: %w", d.SafeString(), resp.err)
	}
	return resp.ips, nil
}

// PopulateFromConfig extracts and caches domains from the client configuration.
func (m *Resolver) PopulateFromConfig(ctx context.Context, mgmtURL *url.URL) error {
	if mgmtURL == nil {
		return nil
	}

	d, err := dnsconfig.ExtractValidDomain(mgmtURL.String())
	if err != nil {
		return fmt.Errorf("extract domain from URL: %w", err)
	}

	m.mutex.Lock()
	m.mgmtDomain = &d
	m.mutex.Unlock()

	if err := m.AddDomain(ctx, d); err != nil {
		return fmt.Errorf("add domain: %w", err)
	}

	return nil
}

// RemoveDomain removes a domain from the cache.
func (m *Resolver) RemoveDomain(d domain.Domain) error {
	dnsName := strings.ToLower(dns.Fqdn(d.PunycodeString()))

	m.mutex.Lock()
	defer m.mutex.Unlock()

	aQuestion := dns.Question{
		Name:   dnsName,
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}
	delete(m.records, aQuestion)

	aaaaQuestion := dns.Question{
		Name:   dnsName,
		Qtype:  dns.TypeAAAA,
		Qclass: dns.ClassINET,
	}
	delete(m.records, aaaaQuestion)

	log.Debugf("removed domain=%s from cache", d.SafeString())
	return nil
}

// GetCachedDomains returns a list of all cached domains.
func (m *Resolver) GetCachedDomains() domain.List {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	domainSet := make(map[domain.Domain]struct{})
	for question := range m.records {
		domainName := strings.TrimSuffix(question.Name, ".")
		domainSet[domain.Domain(domainName)] = struct{}{}
	}

	domains := make(domain.List, 0, len(domainSet))
	for d := range domainSet {
		domains = append(domains, d)
	}

	return domains
}

// UpdateFromServerDomains updates the cache with server domains from network configuration.
// It merges new domains with existing ones, replacing entire domain types when updated.
// Empty updates are ignored to prevent clearing infrastructure domains during partial updates.
func (m *Resolver) UpdateFromServerDomains(ctx context.Context, serverDomains dnsconfig.ServerDomains) (domain.List, error) {
	newDomains := m.extractDomainsFromServerDomains(serverDomains)
	var removedDomains domain.List

	if len(newDomains) > 0 {
		m.mutex.Lock()
		if m.serverDomains == nil {
			m.serverDomains = &dnsconfig.ServerDomains{}
		}
		updatedServerDomains := m.mergeServerDomains(*m.serverDomains, serverDomains)
		m.serverDomains = &updatedServerDomains
		m.mutex.Unlock()

		allDomains := m.extractDomainsFromServerDomains(updatedServerDomains)
		currentDomains := m.GetCachedDomains()
		removedDomains = m.removeStaleDomains(currentDomains, allDomains)
	}

	m.addNewDomains(ctx, newDomains)

	return removedDomains, nil
}

// removeStaleDomains removes cached domains not present in the target domain list.
// Management domains are preserved and never removed during server domain updates.
func (m *Resolver) removeStaleDomains(currentDomains, newDomains domain.List) domain.List {
	var removedDomains domain.List

	for _, currentDomain := range currentDomains {
		if m.isDomainInList(currentDomain, newDomains) {
			continue
		}

		if m.isManagementDomain(currentDomain) {
			continue
		}

		removedDomains = append(removedDomains, currentDomain)
		if err := m.RemoveDomain(currentDomain); err != nil {
			log.Warnf("failed to remove domain=%s: %v", currentDomain.SafeString(), err)
		}
	}

	return removedDomains
}

// mergeServerDomains merges new server domains with existing ones.
// When a domain type is provided in the new domains, it completely replaces that type.
func (m *Resolver) mergeServerDomains(existing, incoming dnsconfig.ServerDomains) dnsconfig.ServerDomains {
	merged := existing

	if incoming.Signal != "" {
		merged.Signal = incoming.Signal
	}
	if len(incoming.Relay) > 0 {
		merged.Relay = incoming.Relay
	}
	if incoming.Flow != "" {
		merged.Flow = incoming.Flow
	}
	if len(incoming.Stuns) > 0 {
		merged.Stuns = incoming.Stuns
	}
	if len(incoming.Turns) > 0 {
		merged.Turns = incoming.Turns
	}

	return merged
}

// isDomainInList checks if domain exists in the list
func (m *Resolver) isDomainInList(domain domain.Domain, list domain.List) bool {
	for _, d := range list {
		if domain.SafeString() == d.SafeString() {
			return true
		}
	}
	return false
}

// isManagementDomain checks if domain is the protected management domain
func (m *Resolver) isManagementDomain(domain domain.Domain) bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.mgmtDomain != nil && domain == *m.mgmtDomain
}

// addNewDomains resolves and caches all domains from the update
func (m *Resolver) addNewDomains(ctx context.Context, newDomains domain.List) {
	for _, newDomain := range newDomains {
		if err := m.AddDomain(ctx, newDomain); err != nil {
			log.Warnf("failed to add/update domain=%s: %v", newDomain.SafeString(), err)
		} else {
			log.Debugf("added/updated management cache domain=%s", newDomain.SafeString())
		}
	}
}

func (m *Resolver) extractDomainsFromServerDomains(serverDomains dnsconfig.ServerDomains) domain.List {
	var domains domain.List

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
