package local

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	"github.com/netbirdio/netbird/client/internal/dns/resutil"
	"github.com/netbirdio/netbird/client/internal/dns/types"
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/shared/management/domain"
)

const externalResolutionTimeout = 4 * time.Second

type resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type Resolver struct {
	mu      sync.RWMutex
	records map[dns.Question][]dns.RR
	domains map[domain.Domain]struct{}
	// zones maps zone domain -> NonAuthoritative (true = non-authoritative, user-created zone)
	zones    map[domain.Domain]bool
	resolver resolver

	ctx    context.Context
	cancel context.CancelFunc
}

func NewResolver() *Resolver {
	ctx, cancel := context.WithCancel(context.Background())
	return &Resolver{
		records: make(map[dns.Question][]dns.RR),
		domains: make(map[domain.Domain]struct{}),
		zones:   make(map[domain.Domain]bool),
		ctx:     ctx,
		cancel:  cancel,
	}
}

func (d *Resolver) MatchSubdomains() bool {
	return true
}

// String returns a string representation of the local resolver
func (d *Resolver) String() string {
	return fmt.Sprintf("LocalResolver [%d records]", len(d.records))
}

func (d *Resolver) Stop() {
	if d.cancel != nil {
		d.cancel()
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	maps.Clear(d.records)
	maps.Clear(d.domains)
	maps.Clear(d.zones)
}

// ID returns the unique handler ID
func (d *Resolver) ID() types.HandlerID {
	return "local-resolver"
}

func (d *Resolver) ProbeAvailability() {}

// ServeDNS handles a DNS request
func (d *Resolver) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	logger := log.WithFields(log.Fields{
		"request_id": resutil.GetRequestID(w),
		"dns_id":     fmt.Sprintf("%04x", r.Id),
	})

	if len(r.Question) == 0 {
		logger.Debug("received local resolver request with no question")
		return
	}
	question := r.Question[0]
	question.Name = strings.ToLower(dns.Fqdn(question.Name))

	replyMessage := &dns.Msg{}
	replyMessage.SetReply(r)
	replyMessage.RecursionAvailable = true

	result := d.lookupRecords(logger, question)
	replyMessage.Authoritative = !result.hasExternalData
	replyMessage.Answer = result.records
	replyMessage.Rcode = d.determineRcode(question, result)

	if replyMessage.Rcode == dns.RcodeNameError && d.shouldFallthrough(question.Name) {
		d.continueToNext(logger, w, r)
		return
	}

	if err := w.WriteMsg(replyMessage); err != nil {
		logger.Warnf("failed to write the local resolver response: %v", err)
	}
}

// determineRcode returns the appropriate DNS response code.
// Per RFC 6604, CNAME chains should return the rcode of the final target resolution,
// even if CNAME records are included in the answer.
func (d *Resolver) determineRcode(question dns.Question, result lookupResult) int {
	// Use the rcode from lookup - this properly handles CNAME chains where
	// the target may be NXDOMAIN or SERVFAIL even though we have CNAME records
	if result.rcode != 0 {
		return result.rcode
	}

	// No records found, but domain exists with different record types (NODATA)
	if d.hasRecordsForDomain(domain.Domain(question.Name), question.Qtype) {
		return dns.RcodeSuccess
	}

	return dns.RcodeNameError
}

// findZone finds the matching zone for a query name using reverse suffix lookup.
// Returns (nonAuthoritative, found). This is O(k) where k = number of labels in qname.
func (d *Resolver) findZone(qname string) (nonAuthoritative bool, found bool) {
	qname = strings.ToLower(dns.Fqdn(qname))
	for {
		if nonAuth, ok := d.zones[domain.Domain(qname)]; ok {
			return nonAuth, true
		}
		// Move to parent domain
		idx := strings.Index(qname, ".")
		if idx == -1 || idx == len(qname)-1 {
			return false, false
		}
		qname = qname[idx+1:]
	}
}

// shouldFallthrough checks if the query should fallthrough to the next handler.
// Returns true if the queried name belongs to a non-authoritative zone.
func (d *Resolver) shouldFallthrough(qname string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	nonAuth, found := d.findZone(qname)
	return found && nonAuth
}

func (d *Resolver) continueToNext(logger *log.Entry, w dns.ResponseWriter, r *dns.Msg) {
	resp := &dns.Msg{}
	resp.SetRcode(r, dns.RcodeNameError)
	resp.MsgHdr.Zero = true
	if err := w.WriteMsg(resp); err != nil {
		logger.Warnf("failed to write continue signal: %v", err)
	}
}

// hasRecordsForDomain checks if any records exist for the given domain name regardless of type
func (d *Resolver) hasRecordsForDomain(domainName domain.Domain, qType uint16) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	_, exists := d.domains[domainName]
	if !exists && supportsWildcard(qType) {
		testWild := transformDomainToWildcard(string(domainName))
		_, exists = d.domains[domain.Domain(testWild)]
	}
	return exists
}

// isInManagedZone checks if the given name falls within any of our managed zones.
// This is used to avoid unnecessary external resolution for CNAME targets that
// are within zones we manage - if we don't have a record for it, it doesn't exist.
// Caller must NOT hold the lock.
func (d *Resolver) isInManagedZone(name string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()

	_, found := d.findZone(name)
	return found
}

// lookupResult contains the result of a DNS lookup operation.
type lookupResult struct {
	records         []dns.RR
	rcode           int
	hasExternalData bool
}

// lookupRecords fetches *all* DNS records matching the first question in r.
func (d *Resolver) lookupRecords(logger *log.Entry, question dns.Question) lookupResult {
	d.mu.RLock()
	records, found := d.records[question]
	usingWildcard := false
	wildQuestion := transformToWildcard(question)
	// RFC 4592 section 2.2.1: wildcard only matches if the name does NOT exist in the zone.
	// If the domain exists with any record type, return NODATA instead of wildcard match.
	if !found && supportsWildcard(question.Qtype) {
		if _, domainExists := d.domains[domain.Domain(question.Name)]; !domainExists {
			records, found = d.records[wildQuestion]
			usingWildcard = found
		}
	}

	if !found {
		d.mu.RUnlock()
		// alternatively check if we have a cname
		if question.Qtype != dns.TypeCNAME {
			cnameQuestion := dns.Question{
				Name:   question.Name,
				Qtype:  dns.TypeCNAME,
				Qclass: question.Qclass,
			}
			return d.lookupCNAMEChain(logger, cnameQuestion, question.Qtype)
		}
		return lookupResult{rcode: dns.RcodeNameError}
	}

	recordsCopy := slices.Clone(records)
	d.mu.RUnlock()

	// if there's more than one record, rotate them (round-robin)
	if len(recordsCopy) > 1 {
		d.mu.Lock()
		q := question
		if usingWildcard {
			q = wildQuestion
		}
		records = d.records[q]
		if len(records) > 1 {
			first := records[0]
			records = append(records[1:], first)
			d.records[q] = records
		}
		d.mu.Unlock()
	}

	if usingWildcard {
		return responseFromWildRecords(question.Name, wildQuestion.Name, recordsCopy)
	}

	return lookupResult{records: recordsCopy, rcode: dns.RcodeSuccess}
}

func transformToWildcard(question dns.Question) dns.Question {
	wildQuestion := question
	wildQuestion.Name = transformDomainToWildcard(wildQuestion.Name)
	return wildQuestion
}

func transformDomainToWildcard(domain string) string {
	s := strings.Split(domain, ".")
	s[0] = "*"
	return strings.Join(s, ".")
}

func supportsWildcard(queryType uint16) bool {
	return queryType != dns.TypeNS && queryType != dns.TypeSOA
}

func responseFromWildRecords(originalName, wildName string, wildRecords []dns.RR) lookupResult {
	records := make([]dns.RR, len(wildRecords))
	for i, record := range wildRecords {
		copiedRecord := dns.Copy(record)
		copiedRecord.Header().Name = originalName
		records[i] = copiedRecord
	}

	return lookupResult{records: records, rcode: dns.RcodeSuccess}
}

// lookupCNAMEChain follows a CNAME chain and returns the CNAME records along with
// the final resolved record of the requested type. This is required for musl libc
// compatibility, which expects the full answer chain rather than just the CNAME.
func (d *Resolver) lookupCNAMEChain(logger *log.Entry, cnameQuestion dns.Question, targetType uint16) lookupResult {
	const maxDepth = 8
	var chain []dns.RR

	for range maxDepth {
		cnameRecords := d.getRecords(cnameQuestion)
		if len(cnameRecords) == 0 && supportsWildcard(targetType) {
			wildQuestion := transformToWildcard(cnameQuestion)
			if wildRecords := d.getRecords(wildQuestion); len(wildRecords) > 0 {
				cnameRecords = responseFromWildRecords(cnameQuestion.Name, wildQuestion.Name, wildRecords).records
			}
		}

		if len(cnameRecords) == 0 {
			break
		}

		chain = append(chain, cnameRecords...)

		cname, ok := cnameRecords[0].(*dns.CNAME)
		if !ok {
			break
		}

		targetName := strings.ToLower(cname.Target)
		targetResult := d.resolveCNAMETarget(logger, targetName, targetType, cnameQuestion.Qclass)

		// keep following chain
		if targetResult.rcode == -1 {
			cnameQuestion = dns.Question{Name: targetName, Qtype: dns.TypeCNAME, Qclass: cnameQuestion.Qclass}
			continue
		}

		return d.buildChainResult(chain, targetResult)
	}

	if len(chain) > 0 {
		return lookupResult{records: chain, rcode: dns.RcodeSuccess}
	}
	return lookupResult{rcode: dns.RcodeSuccess}
}

// buildChainResult combines CNAME chain records with the target resolution result.
// Per RFC 6604, the final rcode is propagated through the chain.
func (d *Resolver) buildChainResult(chain []dns.RR, target lookupResult) lookupResult {
	records := chain
	if len(target.records) > 0 {
		records = append(records, target.records...)
	}

	// preserve hasExternalData for SERVFAIL so caller knows the error came from upstream
	if target.hasExternalData && target.rcode == dns.RcodeServerFailure {
		return lookupResult{
			records:         records,
			rcode:           dns.RcodeServerFailure,
			hasExternalData: true,
		}
	}

	return lookupResult{
		records:         records,
		rcode:           target.rcode,
		hasExternalData: target.hasExternalData,
	}
}

// resolveCNAMETarget attempts to resolve a CNAME target name.
// Returns rcode=-1 to signal "keep following the chain".
func (d *Resolver) resolveCNAMETarget(logger *log.Entry, targetName string, targetType uint16, qclass uint16) lookupResult {
	if records := d.getRecords(dns.Question{Name: targetName, Qtype: targetType, Qclass: qclass}); len(records) > 0 {
		return lookupResult{records: records, rcode: dns.RcodeSuccess}
	}

	// another CNAME, keep following
	if d.hasRecord(dns.Question{Name: targetName, Qtype: dns.TypeCNAME, Qclass: qclass}) {
		return lookupResult{rcode: -1}
	}

	// domain exists locally but not this record type (NODATA)
	if d.hasRecordsForDomain(domain.Domain(targetName), targetType) {
		return lookupResult{rcode: dns.RcodeSuccess}
	}

	// in our zone but doesn't exist (NXDOMAIN)
	if d.isInManagedZone(targetName) {
		return lookupResult{rcode: dns.RcodeNameError}
	}

	return d.resolveExternal(logger, targetName, targetType)
}

func (d *Resolver) getRecords(q dns.Question) []dns.RR {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.records[q]
}

func (d *Resolver) hasRecord(q dns.Question) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, ok := d.records[q]
	return ok
}

// resolveExternal resolves a domain name using the system resolver.
// This is used to resolve CNAME targets that point outside our local zone,
// which is required for musl libc compatibility (musl expects complete answers).
func (d *Resolver) resolveExternal(logger *log.Entry, name string, qtype uint16) lookupResult {
	network := resutil.NetworkForQtype(qtype)
	if network == "" {
		return lookupResult{rcode: dns.RcodeNotImplemented}
	}

	resolver := d.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	ctx, cancel := context.WithTimeout(d.ctx, externalResolutionTimeout)
	defer cancel()

	result := resutil.LookupIP(ctx, resolver, network, name, qtype)
	if result.Err != nil {
		d.logDNSError(logger, name, qtype, result.Err)
		return lookupResult{rcode: result.Rcode, hasExternalData: true}
	}

	return lookupResult{
		records:         resutil.IPsToRRs(name, result.IPs, 60),
		rcode:           dns.RcodeSuccess,
		hasExternalData: true,
	}
}

// logDNSError logs DNS resolution errors for debugging.
func (d *Resolver) logDNSError(logger *log.Entry, hostname string, qtype uint16, err error) {
	qtypeName := dns.TypeToString[qtype]

	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		logger.Debugf("DNS resolution failed for %s type %s: %v", hostname, qtypeName, err)
		return
	}

	if dnsErr.IsNotFound {
		logger.Tracef("DNS target not found: %s type %s", hostname, qtypeName)
		return
	}

	if dnsErr.Server != "" {
		logger.Debugf("DNS resolution failed for %s type %s server=%s: %v", hostname, qtypeName, dnsErr.Server, err)
	} else {
		logger.Debugf("DNS resolution failed for %s type %s: %v", hostname, qtypeName, err)
	}
}

// Update replaces all zones and their records
func (d *Resolver) Update(customZones []nbdns.CustomZone) {
	d.mu.Lock()
	defer d.mu.Unlock()

	maps.Clear(d.records)
	maps.Clear(d.domains)
	maps.Clear(d.zones)

	for _, zone := range customZones {
		zoneDomain := domain.Domain(strings.ToLower(dns.Fqdn(zone.Domain)))
		d.zones[zoneDomain] = zone.NonAuthoritative

		for _, rec := range zone.Records {
			if err := d.registerRecord(rec); err != nil {
				log.Warnf("failed to register the record (%s): %v", rec, err)
			}
		}
	}
}

// RegisterRecord stores a new record by appending it to any existing list
func (d *Resolver) RegisterRecord(record nbdns.SimpleRecord) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.registerRecord(record)
}

// registerRecord performs the registration with the lock already held
func (d *Resolver) registerRecord(record nbdns.SimpleRecord) error {
	rr, err := dns.NewRR(record.String())
	if err != nil {
		return fmt.Errorf("register record: %w", err)
	}

	rr.Header().Rdlength = record.Len()
	header := rr.Header()
	q := dns.Question{
		Name:   strings.ToLower(dns.Fqdn(header.Name)),
		Qtype:  header.Rrtype,
		Qclass: header.Class,
	}

	d.records[q] = append(d.records[q], rr)
	d.domains[domain.Domain(q.Name)] = struct{}{}

	return nil
}
