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
	"golang.zx2c4.com/wireguard/tun/netstack"

	nberrors "github.com/netbirdio/netbird/client/errors"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/dns/resutil"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/route"
)

const errResolveFailed = "failed to resolve query for domain=%s: %v"
const upstreamTimeout = 15 * time.Second

// EDE info codes the forwarder emits on upstream failures so the querying
// client can see the reason without inspecting this peer's logs. They live in
// the RFC 8914 Private Use range (49152-65535); the Go resolver never exposes a
// real upstream EDE here, so these cannot collide with a genuine code.
const (
	edeNetbirdUpstreamTimeout uint16 = 49152
	edeNetbirdUpstreamFailure uint16 = 49153
)

type resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

type firewaller interface {
	UpdateSet(set firewall.Set, prefixes []netip.Prefix) error
}

type DNSForwarder struct {
	listenAddress  netip.AddrPort
	ttl            uint32
	statusRecorder *peer.Status

	mux    *dns.ServeMux
	tcpMux *dns.ServeMux

	mutex sync.RWMutex
	// closed records that Close has run, so a Listen still in flight does not
	// go on to serve sockets nobody will shut down.
	closed bool
	// The sockets are kept alongside the servers because closing them is the
	// only stop that always works: a server whose ActivateAndServe has not run
	// yet refuses to shut down, and would otherwise start serving afterwards.
	udpConn    net.PacketConn
	tcpLn      net.Listener
	dnsServer  *dns.Server
	tcpServer  *dns.Server
	fwdEntries []*ForwarderEntry
	firewall   firewaller
	resolver   resolver
	cache      *cache

	wgIface wgIface
}

func NewDNSForwarder(listenAddress netip.AddrPort, ttl uint32, firewall firewaller, statusRecorder *peer.Status, wgIface wgIface) *DNSForwarder {
	log.Debugf("creating DNS forwarder with listen_address=%s ttl=%d", listenAddress, ttl)
	return &DNSForwarder{
		listenAddress:  listenAddress,
		ttl:            ttl,
		firewall:       firewall,
		statusRecorder: statusRecorder,
		resolver:       net.DefaultResolver,
		cache:          newCache(),
		wgIface:        wgIface,
	}
}

func (f *DNSForwarder) Listen(entries []*ForwarderEntry) error {
	var netstackNet *netstack.Net
	if f.wgIface != nil {
		netstackNet = f.wgIface.GetNet()
	}

	addrDesc := f.listenAddress.String()
	if netstackNet != nil {
		addrDesc = fmt.Sprintf("netstack %s", f.listenAddress)
	}
	log.Infof("starting DNS forwarder on address=%s", addrDesc)

	udpLn, err := f.createUDPListener(netstackNet)
	if err != nil {
		return fmt.Errorf("create UDP listener: %w", err)
	}

	tcpLn, err := f.createTCPListener(netstackNet)
	if err != nil {
		return fmt.Errorf("create TCP listener: %w", err)
	}

	mux := dns.NewServeMux()
	f.mux = mux
	mux.HandleFunc(".", f.handleDNSQueryUDP)
	dnsServer := &dns.Server{
		PacketConn: udpLn,
		Handler:    mux,
	}

	tcpMux := dns.NewServeMux()
	f.tcpMux = tcpMux
	tcpMux.HandleFunc(".", f.handleDNSQueryTCP)
	tcpServer := &dns.Server{
		Listener: tcpLn,
		Handler:  tcpMux,
	}

	if !f.publish(udpLn, tcpLn, dnsServer, tcpServer, entries) {
		log.Infof("DNS forwarder on %s was closed before it started serving", addrDesc)
		if err := udpLn.Close(); err != nil {
			log.Debugf("close UDP listener of a closed forwarder: %v", err)
		}
		if err := tcpLn.Close(); err != nil {
			log.Debugf("close TCP listener of a closed forwarder: %v", err)
		}
		return nil
	}
	log.Debugf("DNS forwarder serving %d domains", len(entries))

	errCh := make(chan error, 2)

	go func() {
		log.Infof("DNS UDP listener running on %s", addrDesc)
		errCh <- dnsServer.ActivateAndServe()
	}()
	go func() {
		log.Infof("DNS TCP listener running on %s", addrDesc)
		errCh <- tcpServer.ActivateAndServe()
	}()

	return <-errCh
}

func (f *DNSForwarder) createUDPListener(netstackNet *netstack.Net) (net.PacketConn, error) {
	if netstackNet != nil {
		return netstackNet.ListenUDPAddrPort(f.listenAddress)
	}

	return net.ListenUDP("udp", net.UDPAddrFromAddrPort(f.listenAddress))
}

func (f *DNSForwarder) createTCPListener(netstackNet *netstack.Net) (net.Listener, error) {
	if netstackNet != nil {
		return netstackNet.ListenTCPAddrPort(f.listenAddress)
	}

	return net.ListenTCP("tcp", net.TCPAddrFromAddrPort(f.listenAddress))
}

// publish hands the sockets, servers and entries to the forwarder so Close can
// reach them and Domains can report them, and says whether serving may begin.
// Listen runs on its own goroutine, so a Close can arrive before it gets this
// far; false means the caller must close what it created instead of serving on
// it.
//
// The entries go in under the same lock rather than afterwards. Anything that
// reads them in between would otherwise see a forwarder that is listening and
// serves no domain, which for a caller rebuilding one means it comes back
// refusing every routed query.
func (f *DNSForwarder) publish(
	udpConn net.PacketConn,
	tcpLn net.Listener,
	dnsServer, tcpServer *dns.Server,
	entries []*ForwarderEntry,
) bool {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	if f.closed {
		return false
	}

	f.udpConn = udpConn
	f.tcpLn = tcpLn
	f.dnsServer = dnsServer
	f.tcpServer = tcpServer
	f.fwdEntries = entries
	return true
}

// Domains returns the entries currently being served. The slice is replaced
// wholesale by UpdateDomains rather than mutated, so the caller may read it but
// must not write to it.
func (f *DNSForwarder) Domains() []*ForwarderEntry {
	f.mutex.RLock()
	defer f.mutex.RUnlock()
	return f.fwdEntries
}

func (f *DNSForwarder) UpdateDomains(entries []*ForwarderEntry) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	// remove cache entries for domains that no longer appear
	f.removeStaleCacheEntries(f.fwdEntries, entries)

	f.fwdEntries = entries
	log.Debugf("Updated DNS forwarder with %d domains", len(entries))
}

// removeStaleCacheEntries unsets cache items for domains that were present
// in the old list but not present in the new list.
func (f *DNSForwarder) removeStaleCacheEntries(oldEntries, newEntries []*ForwarderEntry) {
	if f.cache == nil {
		return
	}

	newSet := make(map[string]struct{}, len(newEntries))
	for _, e := range newEntries {
		if e == nil {
			continue
		}
		newSet[e.Domain.PunycodeString()] = struct{}{}
	}

	for _, e := range oldEntries {
		if e == nil {
			continue
		}
		pattern := e.Domain.PunycodeString()
		if _, ok := newSet[pattern]; !ok {
			f.cache.unset(pattern)
		}
	}
}

func (f *DNSForwarder) Close(ctx context.Context) error {
	// Marked closed under the lock so a Listen that has not published its
	// servers yet gives up instead of racing this shutdown. The shutdowns
	// themselves block, so they run outside it.
	f.mutex.Lock()
	f.closed = true
	dnsServer, tcpServer := f.dnsServer, f.tcpServer
	udpConn, tcpLn := f.udpConn, f.tcpLn
	f.mutex.Unlock()

	var result *multierror.Error

	if dnsServer != nil {
		if err := shutdownServer(ctx, dnsServer); err != nil {
			result = multierror.Append(result, fmt.Errorf("UDP shutdown: %w", err))
		}
	}
	if tcpServer != nil {
		if err := shutdownServer(ctx, tcpServer); err != nil {
			result = multierror.Append(result, fmt.Errorf("TCP shutdown: %w", err))
		}
	}

	// The sockets are closed even when the shutdowns above reported nothing to
	// do. A server that has been published but has not reached
	// ActivateAndServe refuses to shut down, and closing what it was about to
	// serve on is what stops it: the alternative is a listener still answering
	// on an interface that has gone away. A shutdown that did run has already
	// closed these, so the second close is expected to fail.
	if udpConn != nil {
		if err := udpConn.Close(); err != nil {
			log.Debugf("close UDP socket of the DNS forwarder: %v", err)
		}
	}
	if tcpLn != nil {
		if err := tcpLn.Close(); err != nil {
			log.Debugf("close TCP socket of the DNS forwarder: %v", err)
		}
	}

	return nberrors.FormatErrorOrNil(result)
}

func (f *DNSForwarder) handleDNSQuery(logger *log.Entry, w dns.ResponseWriter, query *dns.Msg, startTime time.Time) {
	if len(query.Question) == 0 {
		return
	}
	question := query.Question[0]
	qname := strings.ToLower(question.Name)

	logger.Tracef("question: domain=%s type=%s class=%s",
		qname, dns.TypeToString[question.Qtype], dns.ClassToString[question.Qclass])

	resp := query.SetReply(query)

	mostSpecificResId, matchingEntries := f.getMatchingEntries(strings.TrimSuffix(qname, "."))
	if mostSpecificResId == "" {
		resp.Rcode = dns.RcodeRefused
		f.writeResponse(logger, w, resp, qname, startTime)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), upstreamTimeout)
	defer cancel()

	reqHasEdns := query.IsEdns0() != nil

	switch question.Qtype {
	case dns.TypeA, dns.TypeAAAA:
		f.handleAddressQuery(ctx, logger, w, resp, mostSpecificResId, matchingEntries, reqHasEdns, startTime)
	case dns.TypeMX, dns.TypeTXT, dns.TypeNS, dns.TypeSRV, dns.TypeCNAME, dns.TypePTR:
		f.handleRecordQuery(ctx, logger, w, resp, startTime)
	default:
		// The domain is routed here, so any other type is answered NODATA
		// (NOERROR, empty answer) rather than falling back to a resolver that
		// would poison the name with NXDOMAIN. The Extended DNS Error lets a
		// client tell this capability-driven NODATA apart from an
		// authoritative one. The OPT pseudo-record must not appear unless the
		// query advertised EDNS0.
		if reqHasEdns {
			attachEDE(resp, dns.ExtendedErrorCodeNotSupported, "netbird forwarder: unsupported query type")
		}
		f.writeResponse(logger, w, resp, qname, startTime)
	}
}

// handleAddressQuery resolves A/AAAA queries, programs the firewall sets and
// resolved-IP state, and caches the answer for resilience on upstream failure.
func (f *DNSForwarder) handleAddressQuery(
	ctx context.Context,
	logger *log.Entry,
	w dns.ResponseWriter,
	resp *dns.Msg,
	mostSpecificResId route.ResID,
	matchingEntries []*ForwarderEntry,
	reqHasEdns bool,
	startTime time.Time,
) {
	question := resp.Question[0]
	qname := strings.ToLower(question.Name)

	network := resutil.NetworkForQtype(question.Qtype)
	result := resutil.LookupIP(ctx, f.resolver, network, qname, question.Qtype)
	if result.Err != nil {
		f.handleDNSError(ctx, logger, w, question, resp, qname, result, reqHasEdns, startTime)
		return
	}

	f.updateInternalState(result.IPs, mostSpecificResId, matchingEntries)
	resp.Answer = append(resp.Answer, resutil.IPsToRRs(qname, result.IPs, f.ttl)...)
	f.cache.set(qname, question.Qtype, result.IPs)

	f.writeResponse(logger, w, resp, qname, startTime)
}

// handleRecordQuery resolves non-address record types (MX, TXT, NS, SRV,
// CNAME, PTR) through the host resolver. Missing records are answered NODATA so
// the routed name is never poisoned with NXDOMAIN.
func (f *DNSForwarder) handleRecordQuery(
	ctx context.Context,
	logger *log.Entry,
	w dns.ResponseWriter,
	resp *dns.Msg,
	startTime time.Time,
) {
	question := resp.Question[0]
	qname := strings.ToLower(question.Name)

	records, rcode := resutil.LookupRecords(ctx, f.resolver, qname, question.Qtype, f.ttl)
	resp.Rcode = rcode
	resp.Answer = append(resp.Answer, records...)
	f.writeResponse(logger, w, resp, qname, startTime)
}

func (f *DNSForwarder) writeResponse(logger *log.Entry, w dns.ResponseWriter, resp *dns.Msg, qname string, startTime time.Time) {
	if err := w.WriteMsg(resp); err != nil {
		logger.Errorf("failed to write DNS response: %v", err)
		return
	}

	logger.Tracef("response: domain=%s rcode=%s answers=%s size=%dB took=%s",
		qname, dns.RcodeToString[resp.Rcode], resutil.FormatAnswers(resp.Answer), resp.Len(), time.Since(startTime))
}

// udpResponseWriter wraps a dns.ResponseWriter to handle UDP-specific truncation.
type udpResponseWriter struct {
	dns.ResponseWriter
	query *dns.Msg
}

func (u *udpResponseWriter) WriteMsg(resp *dns.Msg) error {
	opt := u.query.IsEdns0()
	maxSize := dns.MinMsgSize
	if opt != nil {
		maxSize = int(opt.UDPSize())
	}

	if resp.Len() > maxSize {
		resp.Truncate(maxSize)
	}

	return u.ResponseWriter.WriteMsg(resp)
}

func (f *DNSForwarder) handleDNSQueryUDP(w dns.ResponseWriter, query *dns.Msg) {
	startTime := time.Now()
	fields := log.Fields{
		"request_id": resutil.GenerateRequestID(),
		"dns_id":     fmt.Sprintf("%04x", query.Id),
	}
	if addr := w.RemoteAddr(); addr != nil {
		fields["client"] = addr.String()
	}
	logger := log.WithFields(fields)

	f.handleDNSQuery(logger, &udpResponseWriter{ResponseWriter: w, query: query}, query, startTime)
}

func (f *DNSForwarder) handleDNSQueryTCP(w dns.ResponseWriter, query *dns.Msg) {
	startTime := time.Now()
	fields := log.Fields{
		"request_id": resutil.GenerateRequestID(),
		"dns_id":     fmt.Sprintf("%04x", query.Id),
	}
	if addr := w.RemoteAddr(); addr != nil {
		fields["client"] = addr.String()
	}
	logger := log.WithFields(fields)

	f.handleDNSQuery(logger, w, query, startTime)
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

// handleDNSError processes DNS lookup errors and sends an appropriate error response.
func (f *DNSForwarder) handleDNSError(
	ctx context.Context,
	logger *log.Entry,
	w dns.ResponseWriter,
	question dns.Question,
	resp *dns.Msg,
	domain string,
	result resutil.LookupResult,
	reqHasEdns bool,
	startTime time.Time,
) {
	qType := question.Qtype
	qTypeName := dns.TypeToString[qType]

	resp.Rcode = result.Rcode

	// NotFound: cache negative result and respond
	if result.Rcode == dns.RcodeNameError || result.Rcode == dns.RcodeSuccess {
		f.cache.set(domain, question.Qtype, nil)
		f.writeResponse(logger, w, resp, domain, startTime)
		return
	}

	// Upstream failed but we might have a cached answer—serve it if present.
	if ips, ok := f.cache.get(domain, qType); ok {
		if len(ips) > 0 {
			logger.Debugf("serving cached DNS response after upstream failure: domain=%s type=%s", domain, qTypeName)
			resp.Answer = append(resp.Answer, resutil.IPsToRRs(domain, ips, f.ttl)...)
			resp.Rcode = dns.RcodeSuccess
			f.writeResponse(logger, w, resp, domain, startTime)
			return
		}

		// Cached negative result - re-verify NXDOMAIN vs NODATA
		verifyResult := resutil.LookupIP(ctx, f.resolver, resutil.NetworkForQtype(qType), domain, qType)
		if verifyResult.Rcode == dns.RcodeNameError || verifyResult.Rcode == dns.RcodeSuccess {
			resp.Rcode = verifyResult.Rcode
			f.writeResponse(logger, w, resp, domain, startTime)
			return
		}
	}

	// No cache or verification failed. Log with or without the server field for more context.
	var dnsErr *net.DNSError
	if errors.As(result.Err, &dnsErr) && dnsErr.Server != "" {
		logger.Warnf("upstream failure: type=%s domain=%s server=%s: %v", qTypeName, domain, dnsErr.Server, result.Err)
	} else {
		logger.Warnf(errResolveFailed, domain, result.Err)
	}

	if reqHasEdns {
		attachEDE(resp, edeCodeFor(dnsErr), edeText(dnsErr))
	}

	f.writeResponse(logger, w, resp, domain, startTime)
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

// edeCodeFor maps an upstream lookup error to the NetBird EDE info code.
func edeCodeFor(dnsErr *net.DNSError) uint16 {
	if dnsErr != nil && dnsErr.IsTimeout {
		return edeNetbirdUpstreamTimeout
	}
	return edeNetbirdUpstreamFailure
}

// edeText builds the EDE extra-text describing the class of upstream failure.
// It deliberately omits the upstream server address, which may be an internal
// resolver and is exposed to any client permitted to use the route; the full
// detail stays in the forwarder's local log.
func edeText(dnsErr *net.DNSError) string {
	if dnsErr != nil && dnsErr.IsTimeout {
		return "netbird forwarder: upstream timeout"
	}
	return "netbird forwarder: upstream failure"
}

// attachEDE adds an Extended DNS Error (RFC 8914) option to the response,
// creating the OPT pseudo-record if the response does not already carry one.
func attachEDE(resp *dns.Msg, code uint16, text string) {
	opt := resp.IsEdns0()
	if opt == nil {
		resp.SetEdns0(dns.DefaultMsgSize, false)
		opt = resp.IsEdns0()
	}
	opt.Option = append(opt.Option, &dns.EDNS0_EDE{InfoCode: code, ExtraText: text})
}

// shutdownServer shuts a server down gracefully, treating "never started" as
// success. A server that was published but has not reached ActivateAndServe
// has nothing to wind down, and the caller closes its socket regardless, which
// is what actually stops it. dns exports no sentinel for this, so the message
// is all there is to match on.
func shutdownServer(ctx context.Context, server *dns.Server) error {
	err := server.ShutdownContext(ctx)
	if err == nil || strings.Contains(err.Error(), "server not started") {
		return nil
	}
	return err
}
