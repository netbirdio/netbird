package dnsfwd

import (
	"context"
	"errors"
	"math"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer"
	nbdns "github.com/netbirdio/netbird/dns"
)

const errResolveFailed = "failed to resolve query for domain=%s: %v"
const upstreamTimeout = 15 * time.Second

type DNSForwarder struct {
	listenAddress  string
	ttl            uint32
	domains        []string
	statusRecorder *peer.Status

	dnsServer *dns.Server
	mux       *dns.ServeMux

	resId sync.Map
}

func NewDNSForwarder(listenAddress string, ttl uint32, statusRecorder *peer.Status) *DNSForwarder {
	log.Debugf("creating DNS forwarder with listen_address=%s ttl=%d", listenAddress, ttl)
	return &DNSForwarder{
		listenAddress:  listenAddress,
		ttl:            ttl,
		statusRecorder: statusRecorder,
	}
}

func (f *DNSForwarder) Listen(domains []string, resIds map[string]string) error {
	log.Infof("listen DNS forwarder on address=%s", f.listenAddress)
	mux := dns.NewServeMux()

	dnsServer := &dns.Server{
		Addr:    f.listenAddress,
		Net:     "udp",
		Handler: mux,
	}
	f.dnsServer = dnsServer
	f.mux = mux

	f.UpdateDomains(domains, resIds)

	return dnsServer.ListenAndServe()
}

func (f *DNSForwarder) UpdateDomains(domains []string, resIds map[string]string) {
	log.Debugf("Updating domains from %v to %v", f.domains, domains)

	for _, d := range f.domains {
		f.mux.HandleRemove(d)
	}
	f.resId.Clear()

	newDomains := filterDomains(domains)
	for _, d := range newDomains {
		f.mux.HandleFunc(d, f.handleDNSQuery)
	}

	for domain, resId := range resIds {
		if domain != "" {
			f.resId.Store(domain, resId)
		}
	}

	f.domains = newDomains
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
	log.Tracef("received DNS request for DNS forwarder: domain=%v type=%v class=%v",
		query.Question[0].Name, query.Question[0].Qtype, query.Question[0].Qclass)

	question := query.Question[0]
	domain := question.Name

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

	resId := f.getResIdForDomain(strings.TrimSuffix(domain, "."))
	if resId != "" {
		for _, ip := range ips {
			var ipWithSuffix string
			if ip.Is4() {
				ipWithSuffix = ip.String() + "/32"
				log.Tracef("resolved domain=%s to IPv4=%s", domain, ipWithSuffix)
			} else {
				ipWithSuffix = ip.String() + "/128"
				log.Tracef("resolved domain=%s to IPv6=%s", domain, ipWithSuffix)
			}
			f.statusRecorder.AddResolvedIPLookupEntry(ipWithSuffix, resId)
		}
	}

	f.addIPsToResponse(resp, domain, ips)

	if err := w.WriteMsg(resp); err != nil {
		log.Errorf("failed to write DNS response: %v", err)
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

func (f *DNSForwarder) getResIdForDomain(domain string) string {
	var selectedResId string
	var bestScore int

	f.resId.Range(func(key, value interface{}) bool {
		var score int
		pattern := key.(string)

		switch {
		case strings.HasPrefix(pattern, "*."):
			baseDomain := strings.TrimPrefix(pattern, "*.")
			if domain == baseDomain || strings.HasSuffix(domain, "."+baseDomain) {
				score = len(baseDomain)
			}
		case domain == pattern:
			score = math.MaxInt
		default:
			return true
		}

		if score > bestScore {
			bestScore = score
			selectedResId = value.(string)
		}
		return true
	})

	return selectedResId
}

// filterDomains returns a list of normalized domains
func filterDomains(domains []string) []string {
	newDomains := make([]string, 0, len(domains))
	for _, d := range domains {
		if d == "" {
			log.Warn("empty domain in DNS forwarder")
			continue
		}
		newDomains = append(newDomains, nbdns.NormalizeZone(d))
	}
	return newDomains
}
