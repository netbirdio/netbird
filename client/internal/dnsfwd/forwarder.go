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
	nbdns "github.com/netbirdio/netbird/dns"
	"github.com/netbirdio/netbird/management/domain"
	"github.com/netbirdio/netbird/route"
)

const errResolveFailed = "failed to resolve query for domain=%s: %v"
const upstreamTimeout = 15 * time.Second

type DNSForwarder struct {
	listenAddress  string
	ttl            uint32
	statusRecorder *peer.Status

	dnsServer *dns.Server
	mux       *dns.ServeMux

	mutex      sync.RWMutex
	fwdEntries []*ForwarderEntry
	firewall   firewall.Manager
}

func NewDNSForwarder(listenAddress string, ttl uint32, firewall firewall.Manager, statusRecorder *peer.Status) *DNSForwarder {
	log.Debugf("creating DNS forwarder with listen_address=%s ttl=%d", listenAddress, ttl)
	return &DNSForwarder{
		listenAddress:  listenAddress,
		ttl:            ttl,
		firewall:       firewall,
		statusRecorder: statusRecorder,
	}
}

func (f *DNSForwarder) Listen(entries []*ForwarderEntry) error {
	log.Infof("listen DNS forwarder on address=%s", f.listenAddress)
	mux := dns.NewServeMux()

	dnsServer := &dns.Server{
		Addr:    f.listenAddress,
		Net:     "udp",
		Handler: mux,
	}
	f.dnsServer = dnsServer
	f.mux = mux

	f.UpdateDomains(entries)

	return dnsServer.ListenAndServe()
}

func (f *DNSForwarder) UpdateDomains(entries []*ForwarderEntry) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	if f.mux == nil {
		log.Debug("DNS mux is nil, skipping domain update")
		f.fwdEntries = entries
		return
	}

	oldDomains := filterDomains(f.fwdEntries)

	for _, d := range oldDomains {
		f.mux.HandleRemove(d.PunycodeString())
	}

	newDomains := filterDomains(entries)
	for _, d := range newDomains {
		f.mux.HandleFunc(d.PunycodeString(), f.handleDNSQuery)
	}

	f.fwdEntries = entries

	log.Debugf("Updated domains from %v to %v", oldDomains, newDomains)
}

func (f *DNSForwarder) Close(ctx context.Context) error {
	if f.dnsServer == nil {
		return nil
	}
	return f.dnsServer.ShutdownContext(ctx)
}

func (f *DNSForwarder) handleDNSQuery(w dns.ResponseWriter, query *dns.Msg) {
	if len(query.Question) == 0 {
		return
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
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), upstreamTimeout)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, network, domain)
	if err != nil {
		f.handleDNSError(w, resp, domain, err)
		return
	}

	f.updateInternalState(domain, ips)
	f.addIPsToResponse(resp, domain, ips)

	if err := w.WriteMsg(resp); err != nil {
		log.Errorf("failed to write DNS response: %v", err)
	}
}

func (f *DNSForwarder) updateInternalState(domain string, ips []netip.Addr) {
	var prefixes []netip.Prefix
	mostSpecificResId, matchingEntries := f.getMatchingEntries(strings.TrimSuffix(domain, "."))
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
func (f *DNSForwarder) handleDNSError(w dns.ResponseWriter, resp *dns.Msg, domain string, err error) {
	var dnsErr *net.DNSError

	switch {
	case errors.As(err, &dnsErr):
		resp.Rcode = dns.RcodeServerFailure
		if dnsErr.IsNotFound {
			// Pass through NXDOMAIN
			resp.Rcode = dns.RcodeNameError
		}

		if dnsErr.Server != "" {
			log.Warnf("failed to resolve query for domain=%s server=%s: %v", domain, dnsErr.Server, err)
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

// filterDomains returns a list of normalized domains
func filterDomains(entries []*ForwarderEntry) domain.List {
	newDomains := make(domain.List, 0, len(entries))
	for _, d := range entries {
		if d.Domain == "" {
			log.Warn("empty domain in DNS forwarder")
			continue
		}
		newDomains = append(newDomains, domain.Domain(nbdns.NormalizeZone(d.Domain.PunycodeString())))
	}
	return newDomains
}
