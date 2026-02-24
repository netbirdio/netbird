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

type resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type firewaller interface {
	UpdateSet(set firewall.Set, prefixes []netip.Prefix) error
}

type DNSForwarder struct {
	listenAddress  netip.AddrPort
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
	f.dnsServer = &dns.Server{
		PacketConn: udpLn,
		Handler:    mux,
	}

	tcpMux := dns.NewServeMux()
	f.tcpMux = tcpMux
	tcpMux.HandleFunc(".", f.handleDNSQueryTCP)
	f.tcpServer = &dns.Server{
		Listener: tcpLn,
		Handler:  tcpMux,
	}

	f.UpdateDomains(entries)

	errCh := make(chan error, 2)

	go func() {
		log.Infof("DNS UDP listener running on %s", addrDesc)
		errCh <- f.dnsServer.ActivateAndServe()
	}()
	go func() {
		log.Infof("DNS TCP listener running on %s", addrDesc)
		errCh <- f.tcpServer.ActivateAndServe()
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

func (f *DNSForwarder) handleDNSQuery(logger *log.Entry, w dns.ResponseWriter, query *dns.Msg, startTime time.Time) {
	if len(query.Question) == 0 {
		return
	}
	question := query.Question[0]
	qname := strings.ToLower(question.Name)

	logger.Tracef("question: domain=%s type=%s class=%s",
		qname, dns.TypeToString[question.Qtype], dns.ClassToString[question.Qclass])

	resp := query.SetReply(query)
	network := resutil.NetworkForQtype(question.Qtype)
	if network == "" {
		resp.Rcode = dns.RcodeNotImplemented
		f.writeResponse(logger, w, resp, qname, startTime)
		return
	}

	mostSpecificResId, matchingEntries := f.getMatchingEntries(strings.TrimSuffix(qname, "."))
	if mostSpecificResId == "" {
		resp.Rcode = dns.RcodeRefused
		f.writeResponse(logger, w, resp, qname, startTime)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), upstreamTimeout)
	defer cancel()

	result := resutil.LookupIP(ctx, f.resolver, network, qname, question.Qtype)
	if result.Err != nil {
		f.handleDNSError(ctx, logger, w, question, resp, qname, result, startTime)
		return
	}

	f.updateInternalState(result.IPs, mostSpecificResId, matchingEntries)
	resp.Answer = append(resp.Answer, resutil.IPsToRRs(qname, result.IPs, f.ttl)...)
	f.cache.set(qname, question.Qtype, result.IPs)

	f.writeResponse(logger, w, resp, qname, startTime)
}

func (f *DNSForwarder) writeResponse(logger *log.Entry, w dns.ResponseWriter, resp *dns.Msg, qname string, startTime time.Time) {
	if err := w.WriteMsg(resp); err != nil {
		logger.Errorf("failed to write DNS response: %v", err)
		return
	}

	logger.Tracef("response: domain=%s rcode=%s answers=%s took=%s",
		qname, dns.RcodeToString[resp.Rcode], resutil.FormatAnswers(resp.Answer), time.Since(startTime))
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
	logger := log.WithFields(log.Fields{
		"request_id": resutil.GenerateRequestID(),
		"dns_id":     fmt.Sprintf("%04x", query.Id),
	})

	f.handleDNSQuery(logger, &udpResponseWriter{ResponseWriter: w, query: query}, query, startTime)
}

func (f *DNSForwarder) handleDNSQueryTCP(w dns.ResponseWriter, query *dns.Msg) {
	startTime := time.Now()
	logger := log.WithFields(log.Fields{
		"request_id": resutil.GenerateRequestID(),
		"dns_id":     fmt.Sprintf("%04x", query.Id),
	})

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
