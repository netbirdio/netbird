package dnsfwd

import (
	"context"
	"net"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
)

type DNSForwarder struct {
	listenAddress string
	ttl           uint32
	domains       []string

	dnsServer *dns.Server
	mux       *dns.ServeMux
}

func NewDNSForwarder(listenAddress string, ttl uint32, domains []string) *DNSForwarder {
	log.Debugf("creating DNS forwarder with listen address: %s, ttl: %d, domains: %v", listenAddress, ttl, domains)
	return &DNSForwarder{
		listenAddress: listenAddress,
		ttl:           ttl,
		domains:       domains,
	}
}
func (f *DNSForwarder) Listen() error {
	log.Infof("listen DNS forwarder on: %s", f.listenAddress)
	mux := dns.NewServeMux()

	for _, d := range f.domains {
		mux.HandleFunc(nbdns.NormalizeZone(d), f.handleDNSQuery)
	}

	dnsServer := &dns.Server{
		Addr:    f.listenAddress,
		Net:     "udp",
		Handler: mux,
	}
	f.dnsServer = dnsServer
	f.mux = mux
	return dnsServer.ListenAndServe()
}

func (f *DNSForwarder) UpdateDomains(domains []string) {
	for _, d := range f.domains {
		f.mux.HandleRemove(d)
	}

	for _, d := range f.domains {
		f.mux.HandleFunc(nbdns.NormalizeZone(d), f.handleDNSQuery)
	}
	f.domains = domains
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
	log.Tracef("received DNS request for DNS forwarder: %v", query.Question[0].Name)

	question := query.Question[0]
	domain := question.Name

	resp := query.SetReply(query)

	ips, err := net.LookupIP(domain)
	if err != nil {
		log.Warnf("failed to resolve query for domain %s: %v", domain, err)
		resp.Rcode = dns.RcodeServerFailure
		if err := w.WriteMsg(resp); err != nil {
			log.Errorf("failed to write failure DNS response: %v", err)
		}
		return
	}

	for _, ip := range ips {
		var respRecord dns.RR
		if ip.To4() == nil {
			log.Tracef("resolved domain %s to IPv6 %s", domain, ip)
			rr := dns.AAAA{
				AAAA: ip,
				Hdr: dns.RR_Header{
					Name:   domain,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    f.ttl,
				},
			}
			respRecord = &rr
		} else {
			log.Tracef("resolved domain %s to IPv4 %s", domain, ip)
			rr := dns.A{
				A: ip,
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

	if err := w.WriteMsg(resp); err != nil {
		log.Errorf("failed to write DNS response: %v", err)
	}
}
