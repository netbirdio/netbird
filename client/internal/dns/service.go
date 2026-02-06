package dns

import (
	"net/netip"

	"github.com/miekg/dns"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

const (
	DefaultPort = 53
)

// DNSFirewall provides DNAT capabilities for DNS port redirection.
// This is used when the DNS server cannot bind port 53 directly
// and needs firewall rules to redirect traffic.
type DNSFirewall interface {
	AddInboundDNAT(localAddr netip.Addr, protocol firewall.Protocol, sourcePort, targetPort uint16) error
	RemoveInboundDNAT(localAddr netip.Addr, protocol firewall.Protocol, sourcePort, targetPort uint16) error
}

type service interface {
	Listen() error
	Stop()
	RegisterMux(domain string, handler dns.Handler)
	DeregisterMux(key string)
	RuntimePort() int
	RuntimeIP() netip.Addr
}
