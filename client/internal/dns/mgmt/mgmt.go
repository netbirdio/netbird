package mgmt

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"

	dnsconfig "github.com/netbirdio/netbird/client/internal/dns/config"
	"github.com/netbirdio/netbird/client/internal/dns/resutil"
	"github.com/netbirdio/netbird/shared/management/domain"
)

const (
	dnsTimeout     = 5 * time.Second
	defaultTTL     = 300 * time.Second
	refreshBackoff = 30 * time.Second

	// envMgmtCacheTTL overrides defaultTTL for integration/dev testing.
	envMgmtCacheTTL = "NB_MGMT_CACHE_TTL"
)

// ChainResolver lets the cache refresh stale entries through the DNS handler
// chain instead of net.DefaultResolver, avoiding loopback when NetBird is the
// system resolver.
type ChainResolver interface {
	ResolveInternal(ctx context.Context, msg *dns.Msg, maxPriority int) (*dns.Msg, error)
	HasRootHandlerAtOrBelow(maxPriority int) bool
}

// cachedRecord holds DNS records plus timestamps used for TTL refresh.
// records and cachedAt are set at construction and treated as immutable;
// lastFailedRefresh and consecFailures are mutable and must be accessed under
// Resolver.mutex.
type cachedRecord struct {
	records           []dns.RR
	cachedAt          time.Time
	lastFailedRefresh time.Time
	consecFailures    int
}

// Resolver caches critical NetBird infrastructure domains.
// records, refreshing, mgmtDomain and serverDomains are all guarded by mutex.
type Resolver struct {
	records       map[dns.Question]*cachedRecord
	mgmtDomain    *domain.Domain
	serverDomains *dnsconfig.ServerDomains
	mutex         sync.RWMutex

	chain            ChainResolver
	chainMaxPriority int
	refreshGroup     singleflight.Group

	// refreshing tracks questions whose refresh is running via the OS
	// fallback path. A ServeDNS hit for a question in this map indicates
	// the OS resolver routed the recursive query back to us (loop). Only
	// the OS path arms this so chain-path refreshes don't produce false
	// positives. The atomic bool is CAS-flipped once per refresh to
	// throttle the warning log.
	refreshing map[dns.Question]*atomic.Bool

	cacheTTL time.Duration
}

// NewResolver creates a new management domains cache resolver.
func NewResolver() *Resolver {
	return &Resolver{
		records:    make(map[dns.Question]*cachedRecord),
		refreshing: make(map[dns.Question]*atomic.Bool),
		cacheTTL:   resolveCacheTTL(),
	}
}

// String returns a string representation of the resolver.
func (m *Resolver) String() string {
	return "MgmtCacheResolver"
}

// SetChainResolver wires the handler chain used to refresh stale cache entries.
// maxPriority caps which handlers may answer refresh queries (typically
// PriorityUpstream, so upstream/default/fallback handlers are consulted and
// mgmt/route/local handlers are skipped).
func (m *Resolver) SetChainResolver(chain ChainResolver, maxPriority int) {
	m.mutex.Lock()
	m.chain = chain
	m.chainMaxPriority = maxPriority
	m.mutex.Unlock()
}

// ServeDNS serves cached A/AAAA records. Stale entries are returned
// immediately and refreshed asynchronously (stale-while-revalidate).
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
	cached, found := m.records[question]
	inflight := m.refreshing[question]
	var shouldRefresh bool
	if found {
		stale := time.Since(cached.cachedAt) > m.cacheTTL
		inBackoff := !cached.lastFailedRefresh.IsZero() && time.Since(cached.lastFailedRefresh) < refreshBackoff
		shouldRefresh = stale && !inBackoff
	}
	m.mutex.RUnlock()

	if !found {
		m.continueToNext(w, r)
		return
	}

	if inflight != nil && inflight.CompareAndSwap(false, true) {
		log.Warnf("mgmt cache: possible resolver loop for domain=%s: served stale while an OS-fallback refresh was inflight (if NetBird is the system resolver, the OS-path predicate is wrong)",
			question.Name)
	}

	// Skip scheduling a refresh goroutine if one is already inflight for
	// this question; singleflight would dedup anyway but skipping avoids
	// a parked goroutine per stale hit under bursty load.
	if shouldRefresh && inflight == nil {
		m.scheduleRefresh(question, cached)
	}

	resp := &dns.Msg{}
	resp.SetReply(r)
	resp.Authoritative = false
	resp.RecursionAvailable = true
	resp.Answer = cloneRecordsWithTTL(cached.records, m.responseTTL(cached.cachedAt))

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

// AddDomain resolves a domain and stores its A/AAAA records in the cache.
// A family that resolves NODATA (nil err, zero records) evicts any stale
// entry for that qtype.
func (m *Resolver) AddDomain(ctx context.Context, d domain.Domain) error {
	dnsName := strings.ToLower(dns.Fqdn(d.PunycodeString()))

	ctx, cancel := context.WithTimeout(ctx, dnsTimeout)
	defer cancel()

	aRecords, aaaaRecords, errA, errAAAA := m.lookupBoth(ctx, d, dnsName)

	if errA != nil && errAAAA != nil {
		return fmt.Errorf("resolve %s: %w", d.SafeString(), errors.Join(errA, errAAAA))
	}

	if len(aRecords) == 0 && len(aaaaRecords) == 0 {
		if err := errors.Join(errA, errAAAA); err != nil {
			return fmt.Errorf("resolve %s: no A/AAAA records: %w", d.SafeString(), err)
		}
		return fmt.Errorf("resolve %s: no A/AAAA records", d.SafeString())
	}

	now := time.Now()
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.applyFamilyRecords(dnsName, dns.TypeA, aRecords, errA, now)
	m.applyFamilyRecords(dnsName, dns.TypeAAAA, aaaaRecords, errAAAA, now)

	log.Debugf("added/updated domain=%s with %d A records and %d AAAA records",
		d.SafeString(), len(aRecords), len(aaaaRecords))

	return nil
}

// applyFamilyRecords writes records, evicts on NODATA, leaves the cache
// untouched on error. Caller holds m.mutex.
func (m *Resolver) applyFamilyRecords(dnsName string, qtype uint16, records []dns.RR, err error, now time.Time) {
	q := dns.Question{Name: dnsName, Qtype: qtype, Qclass: dns.ClassINET}
	switch {
	case len(records) > 0:
		m.records[q] = &cachedRecord{records: records, cachedAt: now}
	case err == nil:
		delete(m.records, q)
	}
}

// scheduleRefresh kicks off an async refresh. DoChan spawns one goroutine per
// unique in-flight key; bursty stale hits share its channel. expected is the
// cachedRecord pointer observed by the caller; the refresh only mutates the
// cache if that pointer is still the one stored, so a stale in-flight refresh
// can't clobber a newer entry written by AddDomain or a competing refresh.
func (m *Resolver) scheduleRefresh(question dns.Question, expected *cachedRecord) {
	key := question.Name + "|" + dns.TypeToString[question.Qtype]
	_ = m.refreshGroup.DoChan(key, func() (any, error) {
		return nil, m.refreshQuestion(question, expected)
	})
}

// refreshQuestion replaces the cached records on success, or marks the entry
// failed (arming the backoff) on failure. While this runs, ServeDNS can detect
// a resolver loop by spotting a query for this same question arriving on us.
// expected pins the cache entry observed at schedule time; mutations only apply
// if m.records[question] still points at it.
func (m *Resolver) refreshQuestion(question dns.Question, expected *cachedRecord) error {
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()

	d, err := domain.FromString(strings.TrimSuffix(question.Name, "."))
	if err != nil {
		m.markRefreshFailed(question, expected)
		return fmt.Errorf("parse domain: %w", err)
	}

	records, err := m.lookupRecords(ctx, d, question)
	if err != nil {
		fails := m.markRefreshFailed(question, expected)
		logf := log.Warnf
		if fails == 0 || fails > 1 {
			logf = log.Debugf
		}
		logf("refresh mgmt cache domain=%s type=%s: %v (consecutive failures=%d)",
			d.SafeString(), dns.TypeToString[question.Qtype], err, fails)
		return err
	}

	// NOERROR/NODATA: family gone upstream, evict so we stop serving stale.
	if len(records) == 0 {
		m.mutex.Lock()
		if m.records[question] == expected {
			delete(m.records, question)
			m.mutex.Unlock()
			log.Infof("removed mgmt cache domain=%s type=%s: no records returned",
				d.SafeString(), dns.TypeToString[question.Qtype])
			return nil
		}
		m.mutex.Unlock()
		log.Debugf("skipping refresh evict for domain=%s type=%s: entry changed during refresh",
			d.SafeString(), dns.TypeToString[question.Qtype])
		return nil
	}

	now := time.Now()
	m.mutex.Lock()
	if m.records[question] != expected {
		m.mutex.Unlock()
		log.Debugf("skipping refresh write for domain=%s type=%s: entry changed during refresh",
			d.SafeString(), dns.TypeToString[question.Qtype])
		return nil
	}
	m.records[question] = &cachedRecord{records: records, cachedAt: now}
	m.mutex.Unlock()

	log.Infof("refreshed mgmt cache domain=%s type=%s",
		d.SafeString(), dns.TypeToString[question.Qtype])
	return nil
}

func (m *Resolver) markRefreshing(question dns.Question) {
	m.mutex.Lock()
	m.refreshing[question] = &atomic.Bool{}
	m.mutex.Unlock()
}

func (m *Resolver) clearRefreshing(question dns.Question) {
	m.mutex.Lock()
	delete(m.refreshing, question)
	m.mutex.Unlock()
}

// markRefreshFailed arms the backoff and returns the new consecutive-failure
// count so callers can downgrade subsequent failure logs to debug.
func (m *Resolver) markRefreshFailed(question dns.Question, expected *cachedRecord) int {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	c, ok := m.records[question]
	if !ok || c != expected {
		return 0
	}
	c.lastFailedRefresh = time.Now()
	c.consecFailures++
	return c.consecFailures
}

// lookupBoth resolves A and AAAA via chain or OS. Per-family errors let
// callers tell records, NODATA (nil err, no records), and failure apart.
func (m *Resolver) lookupBoth(ctx context.Context, d domain.Domain, dnsName string) (aRecords, aaaaRecords []dns.RR, errA, errAAAA error) {
	m.mutex.RLock()
	chain := m.chain
	maxPriority := m.chainMaxPriority
	m.mutex.RUnlock()

	if chain != nil && chain.HasRootHandlerAtOrBelow(maxPriority) {
		aRecords, errA = m.lookupViaChain(ctx, chain, maxPriority, dnsName, dns.TypeA)
		aaaaRecords, errAAAA = m.lookupViaChain(ctx, chain, maxPriority, dnsName, dns.TypeAAAA)
		return
	}

	// TODO: drop once every supported OS registers a fallback resolver. Safe
	// today: no root handler at priority ≤ PriorityUpstream means NetBird is
	// not the system resolver, so net.DefaultResolver will not loop back.
	aRecords, errA = m.osLookup(ctx, d, dnsName, dns.TypeA)
	aaaaRecords, errAAAA = m.osLookup(ctx, d, dnsName, dns.TypeAAAA)
	return
}

// lookupRecords resolves a single record type via chain or OS. The OS branch
// arms the loop detector for the duration of its call so that ServeDNS can
// spot the OS resolver routing the recursive query back to us.
func (m *Resolver) lookupRecords(ctx context.Context, d domain.Domain, q dns.Question) ([]dns.RR, error) {
	m.mutex.RLock()
	chain := m.chain
	maxPriority := m.chainMaxPriority
	m.mutex.RUnlock()

	if chain != nil && chain.HasRootHandlerAtOrBelow(maxPriority) {
		return m.lookupViaChain(ctx, chain, maxPriority, q.Name, q.Qtype)
	}

	// TODO: drop once every supported OS registers a fallback resolver.
	m.markRefreshing(q)
	defer m.clearRefreshing(q)

	return m.osLookup(ctx, d, q.Name, q.Qtype)
}

// lookupViaChain resolves via the handler chain and rewrites each RR to use
// dnsName as owner and m.cacheTTL as TTL, so CNAME-backed domains don't cache
// target-owned records or upstream TTLs. NODATA returns (nil, nil).
func (m *Resolver) lookupViaChain(ctx context.Context, chain ChainResolver, maxPriority int, dnsName string, qtype uint16) ([]dns.RR, error) {
	msg := &dns.Msg{}
	msg.SetQuestion(dnsName, qtype)
	msg.RecursionDesired = true

	resp, err := chain.ResolveInternal(ctx, msg, maxPriority)
	if err != nil {
		return nil, fmt.Errorf("chain resolve: %w", err)
	}
	if resp == nil {
		return nil, fmt.Errorf("chain resolve returned nil response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("chain resolve rcode=%s", dns.RcodeToString[resp.Rcode])
	}

	ttl := uint32(m.cacheTTL.Seconds())
	owners := cnameOwners(dnsName, resp.Answer)
	var filtered []dns.RR
	for _, rr := range resp.Answer {
		h := rr.Header()
		if h.Class != dns.ClassINET || h.Rrtype != qtype {
			continue
		}
		if !owners[strings.ToLower(dns.Fqdn(h.Name))] {
			continue
		}
		if cp := cloneIPRecord(rr, dnsName, ttl); cp != nil {
			filtered = append(filtered, cp)
		}
	}
	return filtered, nil
}

// osLookup resolves a single family via net.DefaultResolver using resutil,
// which disambiguates NODATA from NXDOMAIN and Unmaps v4-mapped-v6. NODATA
// returns (nil, nil).
func (m *Resolver) osLookup(ctx context.Context, d domain.Domain, dnsName string, qtype uint16) ([]dns.RR, error) {
	network := resutil.NetworkForQtype(qtype)
	if network == "" {
		return nil, fmt.Errorf("unsupported qtype %s", dns.TypeToString[qtype])
	}

	log.Infof("looking up IP for mgmt domain=%s type=%s", d.SafeString(), dns.TypeToString[qtype])
	defer log.Infof("done looking up IP for mgmt domain=%s type=%s", d.SafeString(), dns.TypeToString[qtype])

	result := resutil.LookupIP(ctx, net.DefaultResolver, network, d.PunycodeString(), qtype)
	if result.Rcode == dns.RcodeSuccess {
		return resutil.IPsToRRs(dnsName, result.IPs, uint32(m.cacheTTL.Seconds())), nil
	}

	if result.Err != nil {
		return nil, fmt.Errorf("resolve %s type=%s: %w", d.SafeString(), dns.TypeToString[qtype], result.Err)
	}
	return nil, fmt.Errorf("resolve %s type=%s: rcode=%s", d.SafeString(), dns.TypeToString[qtype], dns.RcodeToString[result.Rcode])
}

// responseTTL returns the remaining cache lifetime in seconds (rounded up),
// so downstream resolvers don't cache an answer for longer than we will.
func (m *Resolver) responseTTL(cachedAt time.Time) uint32 {
	remaining := m.cacheTTL - time.Since(cachedAt)
	if remaining <= 0 {
		return 0
	}
	return uint32((remaining + time.Second - 1) / time.Second)
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

	qA := dns.Question{Name: dnsName, Qtype: dns.TypeA, Qclass: dns.ClassINET}
	qAAAA := dns.Question{Name: dnsName, Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
	delete(m.records, qA)
	delete(m.records, qAAAA)
	delete(m.refreshing, qA)
	delete(m.refreshing, qAAAA)

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

	// Flow receiver domain is intentionally excluded from caching.
	// Cloud providers may rotate the IP behind this domain; a stale cached record
	// causes TLS certificate verification failures on reconnect.

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

// cloneIPRecord returns a deep copy of rr retargeted to owner with ttl. Non
// A/AAAA records return nil.
func cloneIPRecord(rr dns.RR, owner string, ttl uint32) dns.RR {
	switch r := rr.(type) {
	case *dns.A:
		cp := *r
		cp.Hdr.Name = owner
		cp.Hdr.Ttl = ttl
		cp.A = slices.Clone(r.A)
		return &cp
	case *dns.AAAA:
		cp := *r
		cp.Hdr.Name = owner
		cp.Hdr.Ttl = ttl
		cp.AAAA = slices.Clone(r.AAAA)
		return &cp
	}
	return nil
}

// cloneRecordsWithTTL clones A/AAAA records preserving their owner and
// stamping ttl so the response shares no memory with the cached slice.
func cloneRecordsWithTTL(records []dns.RR, ttl uint32) []dns.RR {
	out := make([]dns.RR, 0, len(records))
	for _, rr := range records {
		if cp := cloneIPRecord(rr, rr.Header().Name, ttl); cp != nil {
			out = append(out, cp)
		}
	}
	return out
}

// cnameOwners returns dnsName plus every target reachable by following CNAMEs
// in answer, iterating until fixed point so out-of-order chains resolve.
func cnameOwners(dnsName string, answer []dns.RR) map[string]bool {
	owners := map[string]bool{dnsName: true}
	for {
		added := false
		for _, rr := range answer {
			cname, ok := rr.(*dns.CNAME)
			if !ok {
				continue
			}
			name := strings.ToLower(dns.Fqdn(cname.Hdr.Name))
			if !owners[name] {
				continue
			}
			target := strings.ToLower(dns.Fqdn(cname.Target))
			if !owners[target] {
				owners[target] = true
				added = true
			}
		}
		if !added {
			return owners
		}
	}
}

// resolveCacheTTL reads the cache TTL override env var; invalid or empty
// values fall back to defaultTTL. Called once per Resolver from NewResolver.
func resolveCacheTTL() time.Duration {
	if v := os.Getenv(envMgmtCacheTTL); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return defaultTTL
}
