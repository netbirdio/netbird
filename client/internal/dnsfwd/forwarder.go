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
}

func NewDNSForwarder(listenAddress string, ttl uint32, firewall firewaller, statusRecorder *peer.Status) *DNSForwarder {
	log.Debugf("creating DNS forwarder with listen_address=%s ttl=%d", listenAddress, ttl)
	return &DNSForwarder{
		listenAddress:  listenAddress,
		ttl:            ttl,
		firewall:       firewall,
		statusRecorder: statusRecorder,
		resolver:       net.DefaultResolver,
	}
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
	ips, err := f.resolver.LookupNetIP(ctx, network, domain)
	if err != nil {
		f.handleDNSError(w, query, resp, domain, err)
		return nil
	}

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

// handleDNSError processes DNS lookup errors and sends an appropriate error response
func (f *DNSForwarder) handleDNSError(w dns.ResponseWriter, query, resp *dns.Msg, domain string, err error) {
	var dnsErr *net.DNSError

	switch {
	case errors.As(err, &dnsErr):
		resp.Rcode = dns.RcodeServerFailure
		if dnsErr.IsNotFound {
			// Pass through NXDOMAIN
			resp.Rcode = dns.RcodeNameError
		}

		if dnsErr.Server != "" {
			log.Warnf("failed to resolve query for type=%s domain=%s server=%s: %v", dns.TypeToString[query.Question[0].Qtype], domain, dnsErr.Server, err)
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
