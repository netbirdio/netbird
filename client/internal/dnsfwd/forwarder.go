package dnsfwd

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/route"
)

const errResolveFailed = "failed to resolve query for domain=%s: %v"
const upstreamTimeout = 15 * time.Second

type resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type firewaller interface {
	UpdateSet(set firewall.Set, prefixes []netip.Prefix) error
}

type DNSForwarder struct {
	listenAddress  string
	ttl            uint32
	statusRecorder *peer.Status

	dnsServer *dns.Server
	mux       *dns.ServeMux
	tcpServer *dns.Server
	tcpMux    *dns.ServeMux

	mutex      sync.RWMutex
	fwdEntries []*ForwarderEntry
	firewall   firewaller
	resolver   resolver

	// failure rate tracking for routed domains
	failureMu      sync.Mutex
	failureCounts  map[string]int
	failureWindow  time.Duration
	lastLogPerHost map[string]time.Time

	// per-domain rolling stats and windows
	statsMu sync.Mutex
	stats   map[string]*domainStats
	winSize time.Duration
	slowT   time.Duration
}

func NewDNSForwarder(listenAddress string, ttl uint32, firewall firewaller, statusRecorder *peer.Status) *DNSForwarder {
	log.Debugf("creating DNS forwarder with listen_address=%s ttl=%d", listenAddress, ttl)
	return &DNSForwarder{
		listenAddress:  listenAddress,
		ttl:            ttl,
		firewall:       firewall,
		statusRecorder: statusRecorder,
		resolver:       net.DefaultResolver,
		failureCounts:  make(map[string]int),
		failureWindow:  10 * time.Second,
		lastLogPerHost: make(map[string]time.Time),
		stats:          make(map[string]*domainStats),
		winSize:        10 * time.Second,
		slowT:          300 * time.Millisecond,
	}
}

type domainStats struct {
	total    int
	success  int
	timeouts int
	notfound int
	failures int // other failures (incl. SERVFAIL-like)
	slow     int
	lastLog  time.Time
}

func (f *DNSForwarder) Listen(entries []*ForwarderEntry) error {
	log.Infof("starting DNS forwarder on address=%s", f.listenAddress)

	// UDP server
	mux := dns.NewServeMux()
	f.mux = mux
	mux.HandleFunc(".", f.handleDNSQueryUDP)
	f.dnsServer = &dns.Server{
		Addr:    f.listenAddress,
		Net:     "udp",
		Handler: mux,
	}

	// TCP server
	tcpMux := dns.NewServeMux()
	f.tcpMux = tcpMux
	tcpMux.HandleFunc(".", f.handleDNSQueryTCP)
	f.tcpServer = &dns.Server{
		Addr:    f.listenAddress,
		Net:     "tcp",
		Handler: tcpMux,
	}

	f.UpdateDomains(entries)

	errCh := make(chan error, 2)

	go func() {
		log.Infof("DNS UDP listener running on %s", f.listenAddress)
		errCh <- f.dnsServer.ListenAndServe()
	}()
	go func() {
		log.Infof("DNS TCP listener running on %s", f.listenAddress)
		errCh <- f.tcpServer.ListenAndServe()
	}()

	// return the first error we get (e.g. bind failure or shutdown)
	return <-errCh
}

func (f *DNSForwarder) UpdateDomains(entries []*ForwarderEntry) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	f.fwdEntries = entries
	log.Debugf("Updated DNS forwarder with %d domains", len(entries))
}

func (f *DNSForwarder) Close(ctx context.Context) error {
	var result *multierror.Error

	if f.dnsServer != nil {
		if err := f.dnsServer.ShutdownContext(ctx); err != nil {
			result = multierror.Append(result, fmt.Errorf("UDP shutdown: %w", err))
		}
	}
	if f.tcpServer != nil {
		if err := f.tcpServer.ShutdownContext(ctx); err != nil {
			result = multierror.Append(result, fmt.Errorf("TCP shutdown: %w", err))
		}
	}

	return nberrors.FormatErrorOrNil(result)
}

func (f *DNSForwarder) handleDNSQuery(w dns.ResponseWriter, query *dns.Msg) *dns.Msg {
	if len(query.Question) == 0 {
		return nil
	}
	question := query.Question[0]
	log.Tracef("received DNS request for DNS forwarder: domain=%v type=%v class=%v",
		question.Name, question.Qtype, question.Qclass)

	domain := strings.ToLower(question.Name)

	resp := query.SetReply(query)
	var network string
	switch question.Qtype {
	case dns.TypeA:
		network = "ip4"
	case dns.TypeAAAA:
		network = "ip6"
	default:
		// TODO: Handle other types

		resp.Rcode = dns.RcodeNotImplemented
		if err := w.WriteMsg(resp); err != nil {
			log.Errorf("failed to write DNS response: %v", err)
		}
		return nil
	}

	mostSpecificResId, matchingEntries := f.getMatchingEntries(strings.TrimSuffix(domain, "."))
	// query doesn't match any configured domain
	if mostSpecificResId == "" {
		resp.Rcode = dns.RcodeRefused
		if err := w.WriteMsg(resp); err != nil {
			log.Errorf("failed to write DNS response: %v", err)
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), upstreamTimeout)
	defer cancel()
	start := time.Now()
	ips, err := f.resolver.LookupNetIP(ctx, network, domain)
	elapsed := time.Since(start)
	if err != nil {
		f.handleDNSError(ctx, w, question, resp, domain, err)
		// record error stats for routed domains
		f.recordErrorStats(strings.TrimSuffix(domain, "."), err)
		return nil
	}

	// record success timing
	f.recordSuccessStats(strings.TrimSuffix(domain, "."), elapsed)

	f.updateInternalState(ips, mostSpecificResId, matchingEntries)
	f.addIPsToResponse(resp, domain, ips)

	return resp
}

func (f *DNSForwarder) handleDNSQueryUDP(w dns.ResponseWriter, query *dns.Msg) {
	resp := f.handleDNSQuery(w, query)
	if resp == nil {
		return
	}

	opt := query.IsEdns0()
	maxSize := dns.MinMsgSize
	if opt != nil {
		// client advertised a larger EDNS0 buffer
		maxSize = int(opt.UDPSize())
	}

	// if our response is too big, truncate and set the TC bit
	if resp.Len() > maxSize {
		resp.Truncate(maxSize)
	}

	if err := w.WriteMsg(resp); err != nil {
		log.Errorf("failed to write DNS response: %v", err)
	}
}

func (f *DNSForwarder) handleDNSQueryTCP(w dns.ResponseWriter, query *dns.Msg) {
	resp := f.handleDNSQuery(w, query)
	if resp == nil {
		return
	}

	if err := w.WriteMsg(resp); err != nil {
		log.Errorf("failed to write DNS response: %v", err)
	}
}

func (f *DNSForwarder) updateInternalState(ips []netip.Addr, mostSpecificResId route.ResID, matchingEntries []*ForwarderEntry) {
	var prefixes []netip.Prefix
	if mostSpecificResId != "" {
		for _, ip := range ips {
			var prefix netip.Prefix
			if ip.Is4() {
				prefix = netip.PrefixFrom(ip, 32)
			} else {
				prefix = netip.PrefixFrom(ip, 128)
			}
			prefixes = append(prefixes, prefix)
			f.statusRecorder.AddResolvedIPLookupEntry(prefix, mostSpecificResId)
		}
	}

	if f.firewall != nil {
		f.updateFirewall(matchingEntries, prefixes)
	}
}

func (f *DNSForwarder) updateFirewall(matchingEntries []*ForwarderEntry, prefixes []netip.Prefix) {
	var merr *multierror.Error
	for _, entry := range matchingEntries {
		if err := f.firewall.UpdateSet(entry.Set, prefixes); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("update set for domain=%s: %w", entry.Domain, err))
		}
	}
	if merr != nil {
		log.Errorf("failed to update firewall sets (%d/%d): %v",
			len(merr.Errors),
			len(matchingEntries),
			nberrors.FormatErrorOrNil(merr))
	}
}

// setResponseCodeForNotFound determines and sets the appropriate response code when IsNotFound is true
// It distinguishes between NXDOMAIN (domain doesn't exist) and NODATA (domain exists but no records of requested type)
//
// LIMITATION: This function only checks A and AAAA record types to determine domain existence.
// If a domain has only other record types (MX, TXT, CNAME, etc.) but no A/AAAA records,
// it may incorrectly return NXDOMAIN instead of NODATA. This is acceptable since the forwarder
// only handles A/AAAA queries and returns NOTIMP for other types.
func (f *DNSForwarder) setResponseCodeForNotFound(ctx context.Context, resp *dns.Msg, domain string, originalQtype uint16) {
	// Try querying for a different record type to see if the domain exists
	// If the original query was for AAAA, try A. If it was for A, try AAAA.
	// This helps distinguish between NXDOMAIN and NODATA.
	var alternativeNetwork string
	switch originalQtype {
	case dns.TypeAAAA:
		alternativeNetwork = "ip4"
	case dns.TypeA:
		alternativeNetwork = "ip6"
	default:
		resp.Rcode = dns.RcodeNameError
		return
	}

	if _, err := f.resolver.LookupNetIP(ctx, alternativeNetwork, domain); err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			// Alternative query also returned not found - domain truly doesn't exist
			resp.Rcode = dns.RcodeNameError
			return
		}
		// Some other error (timeout, server failure, etc.) - can't determine, assume domain exists
		resp.Rcode = dns.RcodeSuccess
		return
	}

	// Alternative query succeeded - domain exists but has no records of this type
	resp.Rcode = dns.RcodeSuccess
}

// handleDNSError processes DNS lookup errors and sends an appropriate error response
func (f *DNSForwarder) handleDNSError(ctx context.Context, w dns.ResponseWriter, question dns.Question, resp *dns.Msg, domain string, err error) {
	var dnsErr *net.DNSError

	switch {
	case errors.As(err, &dnsErr):
		resp.Rcode = dns.RcodeServerFailure
		if dnsErr.IsNotFound {
			f.setResponseCodeForNotFound(ctx, resp, domain, question.Qtype)
		}

		if dnsErr.Server != "" {
			log.Warnf("failed to resolve query for type=%s domain=%s server=%s: %v", dns.TypeToString[question.Qtype], domain, dnsErr.Server, err)
		} else {
			log.Warnf(errResolveFailed, domain, err)
		}
	default:
		resp.Rcode = dns.RcodeServerFailure
		log.Warnf(errResolveFailed, domain, err)
	}

	if err := w.WriteMsg(resp); err != nil {
		log.Errorf("failed to write failure DNS response: %v", err)
	}

	// Track failure rate for routed domains only
	if resID, _ := f.getMatchingEntries(strings.TrimSuffix(domain, ".")); resID != "" {
		f.recordDomainFailure(strings.TrimSuffix(domain, "."))
	}
}

// recordErrorStats updates per-domain counters and emits rate-limited logs
func (f *DNSForwarder) recordErrorStats(domain string, err error) {
	domain = strings.ToLower(domain)
	f.statsMu.Lock()
	s := f.ensureStats(domain)
	s.total++

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			s.notfound++
		} else if dnsErr.Timeout() {
			s.timeouts++
		} else {
			s.failures++
		}
	} else {
		s.failures++
	}

	f.maybeLogDomainStats(domain, s)
	f.statsMu.Unlock()
}

// recordSuccessStats updates per-domain latency stats and slow counters, logs if needed (rate-limited)
func (f *DNSForwarder) recordSuccessStats(domain string, elapsed time.Duration) {
	domain = strings.ToLower(domain)
	f.statsMu.Lock()
	s := f.ensureStats(domain)
	s.total++
	s.success++
	if elapsed >= f.slowT {
		s.slow++
	}
	f.maybeLogDomainStats(domain, s)
	f.statsMu.Unlock()
}

func (f *DNSForwarder) ensureStats(domain string) *domainStats {
	if ds, ok := f.stats[domain]; ok {
		return ds
	}
	ds := &domainStats{}
	f.stats[domain] = ds
	return ds
}

// maybeLogDomainStats logs a compact summary per routed domain at most once per window
func (f *DNSForwarder) maybeLogDomainStats(domain string, s *domainStats) {
	now := time.Now()
	if !s.lastLog.IsZero() && now.Sub(s.lastLog) < f.winSize {
		return
	}

	// check if routed (avoid logging for non-routed domains)
	if resID, _ := f.getMatchingEntries(domain); resID == "" {
		return
	}

	// only log if something noteworthy happened in the window
	noteworthy := s.timeouts > 0 || s.notfound > 0 || s.failures > 0 || s.slow > 0
	if !noteworthy {
		s.lastLog = now
		return
	}

	// warn on persistent problems, info otherwise
	levelWarn := s.timeouts >= 3 || s.failures >= 3
	if levelWarn {
		log.Warnf("[d] DNS stats: domain=%s total=%d ok=%d timeout=%d nxdomain=%d fail=%d slow=%d(>=%s)",
			domain, s.total, s.success, s.timeouts, s.notfound, s.failures, s.slow, f.slowT)
	} else {
		log.Infof("[d] DNS stats: domain=%s total=%d ok=%d timeout=%d nxdomain=%d fail=%d slow=%d(>=%s)",
			domain, s.total, s.success, s.timeouts, s.notfound, s.failures, s.slow, f.slowT)
	}

	// reset counters for next window
	*s = domainStats{lastLog: now}
}

// addIPsToResponse adds IP addresses to the DNS response as appropriate A or AAAA records
func (f *DNSForwarder) addIPsToResponse(resp *dns.Msg, domain string, ips []netip.Addr) {
	for _, ip := range ips {
		var respRecord dns.RR
		if ip.Is6() {
			log.Tracef("resolved domain=%s to IPv6=%s", domain, ip)
			rr := dns.AAAA{
				AAAA: ip.AsSlice(),
				Hdr: dns.RR_Header{
					Name:   domain,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    f.ttl,
				},
			}
			respRecord = &rr
		} else {
			log.Tracef("resolved domain=%s to IPv4=%s", domain, ip)
			rr := dns.A{
				A: ip.AsSlice(),
				Hdr: dns.RR_Header{
					Name:   domain,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    f.ttl,
				},
			}
			respRecord = &rr
		}
		resp.Answer = append(resp.Answer, respRecord)
	}
}

// recordDomainFailure increments failure count for the domain and logs at info/warn with throttling.
func (f *DNSForwarder) recordDomainFailure(domain string) {
	domain = strings.ToLower(domain)

	f.failureMu.Lock()
	defer f.failureMu.Unlock()

	f.failureCounts[domain]++
	count := f.failureCounts[domain]

	now := time.Now()
	last, ok := f.lastLogPerHost[domain]
	if ok && now.Sub(last) < f.failureWindow {
		return
	}
	f.lastLogPerHost[domain] = now

	log.Warnf("[d] DNS failures observed for routed domain: domain=%s failures=%d/%s", domain, count, f.failureWindow)

}

// getMatchingEntries retrieves the resource IDs for a given domain.
// It returns the most specific match and all matching resource IDs.
func (f *DNSForwarder) getMatchingEntries(domain string) (route.ResID, []*ForwarderEntry) {
	var selectedResId route.ResID
	var bestScore int
	var matches []*ForwarderEntry

	f.mutex.RLock()
	defer f.mutex.RUnlock()

	for _, entry := range f.fwdEntries {
		var score int
		pattern := entry.Domain.PunycodeString()

		switch {
		case strings.HasPrefix(pattern, "*."):
			baseDomain := strings.TrimPrefix(pattern, "*.")

			if strings.EqualFold(domain, baseDomain) || strings.HasSuffix(domain, "."+baseDomain) {
				score = len(baseDomain)
				matches = append(matches, entry)
			}
		case domain == pattern:
			score = math.MaxInt
			matches = append(matches, entry)
		default:
			continue
		}

		if score > bestScore {
			bestScore = score
			selectedResId = entry.ResID
		}
	}

	return selectedResId, matches
}
