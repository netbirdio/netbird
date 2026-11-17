package nmdata

import "net/netip"

// NameServerGroup is the slim twin of dns.NameServerGroup.
type NameServerGroup struct {
	ID                   string
	PublicID             string
	Name                 string
	Description          string
	NameServers          []NameServer
	Groups               []string
	Primary              bool
	Domains              []string
	Enabled              bool
	SearchDomainsEnabled bool
}

// NameServer is the slim twin of dns.NameServer.
type NameServer struct {
	IP     netip.Addr
	NSType int
	Port   int
}
