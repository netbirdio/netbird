//go:build ios

package dynamic

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/client/internal/dns"

	"github.com/netbirdio/netbird/management/domain"
)

const dialTimeout = 1 * time.Second

func (r *Route) getIPsFromResolver(domain domain.Domain) ([]net.IP, error) {
	privateClient, err := nbdns.GetClientPrivate(r.wgInterface.Address().IP, r.wgInterface.Name(), dialTimeout)
	if err != nil {
		log.Debugf("DNS query for %s failed: %s", domain.SafeString(), err)
		return nil, err
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(string(domain)), dns.TypeA)

	startTime := time.Now()

	response, _, err := privateClient.Exchange(msg, fmt.Sprintf("%s:%d", r.serviceViaMemory.RuntimeIP(), r.serviceViaMemory.RuntimePort()))
	if err != nil {
		log.Debugf("DNS query for %s failed after %s: %s ", domain.SafeString(), time.Since(startTime), err)
		return nil, err
	}

	log.Debugf("DNS query for %s took %s", domain.SafeString(), time.Since(startTime))

	if response.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns response code: %s", dns.RcodeToString[response.Rcode])
	}

	for _, ans := range response.Answer {
		if aRecord, ok := ans.(*dns.A); ok {
			return []net.IP{aRecord.A}, nil
		}
	}

	return nil, fmt.Errorf("no A record found")
}
