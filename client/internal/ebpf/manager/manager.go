package manager

import "net/netip"

// Manager is used to load eBPF programs. Currently only the DNS forwarder uses one.
type Manager interface {
	LoadDNSFwd(ip netip.Addr, dnsPort int) error
	FreeDNSFwd() error
}
