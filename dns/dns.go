// Package dns implement dns types and standard methods and functions
// to parse and normalize dns records and configuration
package dns

import (
	"fmt"
	"github.com/miekg/dns"
)

const (
	// DefaultDNSPort well-known port number
	DefaultDNSPort = 53
	// RootZone is a string representation of the root zone
	RootZone = "."
)

type Update struct {
	ServiceEnable    bool
	NameServerGroups []NameServerGroup
	CustomZones      []CustomZone
}

type CustomZone struct {
	Domain  string
	Records []SimpleRecord
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
	return fmt.Sprintf("%s %d %s %s %s", fqdn, s.TTL, s.Class, dns.Type(s.Type).String(), s.RData)
}
