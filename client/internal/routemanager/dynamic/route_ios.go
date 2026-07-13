//go:build ios

package dynamic

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"

	nbdns "github.com/netbirdio/netbird/client/internal/dns"

	"github.com/netbirdio/netbird/shared/management/domain"
)

const dialTimeout = 10 * time.Second

func (r *Route) getIPsFromResolver(domain domain.Domain) ([]net.IP, error) {
	privateClient, err := nbdns.GetClientPrivate(r.wgInterface, r.resolverAddr.Addr(), dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("error while creating private client: %s", err)
	}

	fqdn := dns.Fqdn(domain.PunycodeString())
	startTime := time.Now()

	var ips []net.IP
	var queryErr error

	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		msg := new(dns.Msg)
		msg.SetQuestion(fqdn, qtype)

		response, _, err := nbdns.ExchangeWithFallback(nil, privateClient, msg, r.resolverAddr.String())
		if err != nil {
			if queryErr == nil {
				queryErr = fmt.Errorf("DNS query for %s (type %d) after %s: %w", domain.SafeString(), qtype, time.Since(startTime), err)
			}
			continue
		}

		if response.Rcode != dns.RcodeSuccess {
			continue
		}

		for _, answ := range response.Answer {
			if aRecord, ok := answ.(*dns.A); ok {
				ips = append(ips, aRecord.A)
			}
			if aaaaRecord, ok := answ.(*dns.AAAA); ok {
				ips = append(ips, aaaaRecord.AAAA)
			}
		}
	}

	if len(ips) == 0 {
		if queryErr != nil {
			return nil, queryErr
		}
		return nil, fmt.Errorf("no A or AAAA records found for %s", domain.SafeString())
	}

	return ips, nil
}
