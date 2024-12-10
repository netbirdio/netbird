package dnsfwd

import (
	"context"
	"net"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

type DNSForwarder struct {
	ListenAddress string
	TTL           uint32

	dnsServer *dns.Server
}

func (f *DNSForwarder) Listen() error {
	log.Infof("listen DNS forwarder on: %s", f.ListenAddress)
	mux := dns.NewServeMux()
	mux.HandleFunc(".", f.handleDNSQuery)

	dnsServer := &dns.Server{
		Addr:    f.ListenAddress,
		Net:     "udp",
		Handler: mux,
	}
	f.dnsServer = dnsServer
	return dnsServer.ListenAndServe()
}

func (f *DNSForwarder) Close(ctx context.Context) error {
	if f.dnsServer == nil {
		return nil
	}
	return f.dnsServer.ShutdownContext(ctx)
}

func (f *DNSForwarder) handleDNSQuery(w dns.ResponseWriter, query *dns.Msg) {
	log.Debugf("received DNS query for DNS forwarder: %v", query)
	if len(query.Question) == 0 {
		return
	}

	question := query.Question[0]
	domain := question.Name

	resp := query.SetReply(query)

	ips, err := net.LookupIP(domain)
	if err != nil {
		log.Errorf("failed to resolve query for domain %s: %v", domain, err)
		resp.Rcode = dns.RcodeServerFailure
		_ = w.WriteMsg(resp)
		return
	}

	for _, ip := range ips {
		log.Infof("resolved domain %s to IP %s", domain, ip)
		var respRecord dns.RR
		if ip.To4() == nil {
			log.Infof("resolved domain %s to IPv6 %s", domain, ip)
			rr := dns.AAAA{
				AAAA: ip,
				Hdr: dns.RR_Header{
					Name:   domain,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    f.TTL,
				},
			}
			respRecord = &rr
		} else {
			rr := dns.A{
				A: ip,
				Hdr: dns.RR_Header{
					Name:   domain,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    f.TTL,
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
