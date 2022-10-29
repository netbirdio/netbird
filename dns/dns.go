// Package dns implement dns types and standard methods and functions
// to parse and normalize dns records and configuration
package dns

import (
	"fmt"
	"github.com/miekg/dns"
)

// DefaultDNSPort well-known port number
const DefaultDNSPort = 53

type Update struct {
	NameServerGroups []NameServerGroup
	CustomDomains    []CustomDomain
}

type CustomDomain struct {
	SearchDomain []string
	Records      []SimpleRecord
}

// DefaultClass is the class supported by the system
const DefaultClass = "IN"

// SimpleRecord provides a simple DNS record specification for CNAME, A and AAAA records
type SimpleRecord struct {
	Name  string
	Type  int
	Class string
	TTL   int
	RData string
}

// String returns a string of the simple record formatted as:
// <Name> <Type> <Class> <TTL> <RDATA>
func (s SimpleRecord) String() string {
	fqdn := dns.Fqdn(s.Name)
	return fmt.Sprintf("%s %s %s %d %s", fqdn, dns.Type(s.Type).String(), s.Class, s.TTL, s.RData)
}
