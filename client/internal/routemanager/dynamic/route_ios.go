//go:build ios || tvos

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
	privateClient, err := nbdns.GetClientPrivate(r.wgInterface.Address().IP, r.wgInterface.Name(), dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("error while creating private client: %s", err)
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain.PunycodeString()), dns.TypeA)

	startTime := time.Now()

	response, _, err := nbdns.ExchangeWithFallback(nil, privateClient, msg, r.resolverAddr)
	if err != nil {
		return nil, fmt.Errorf("DNS query for %s failed after %s: %s ", domain.SafeString(), time.Since(startTime), err)
	}

	if response.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns response code: %s", dns.RcodeToString[response.Rcode])
	}

	ips := make([]net.IP, 0)

	for _, answ := range response.Answer {
		if aRecord, ok := answ.(*dns.A); ok {
			ips = append(ips, aRecord.A)
		}
		if aaaaRecord, ok := answ.(*dns.AAAA); ok {
			ips = append(ips, aaaaRecord.AAAA)
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no A or AAAA records found for %s", domain.SafeString())
	}

	return ips, nil
}
