package types

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
)

// SimpleRecord provides a simple DNS record specification for CNAME, A and AAAA records
type SimpleRecord struct {
	// Name domain name
	Name string
	// Type of record, 1 for A, 5 for CNAME, 28 for AAAA. see https://pkg.go.dev/github.com/miekg/dns@v1.1.41#pkg-constants
	Type int
	// Class dns class, currently use the DefaultClass for all records
	Class string
	// TTL time-to-live for the record
	TTL int
	// RData is the actual value resolved in a dns query
	RData string
}

// String returns a string of the simple record formatted as:
// <Name> <TTL> <Class> <Type> <RDATA>
func (s SimpleRecord) String() string {
	fqdn := dns.Fqdn(s.Name)
	return fmt.Sprintf("%s %d %s %s %s", fqdn, s.TTL, s.Class, dns.Type(s.Type).String(), s.RData)
}

// Len returns the length of the RData field, based on its type
func (s SimpleRecord) Len() uint16 {
	emptyString := s.RData == ""
	switch s.Type {
	case 1:
		if emptyString {
			return 0
		}
		return net.IPv4len
	case 5:
		if emptyString || s.RData == "." {
			return 1
		}
		return uint16(len(s.RData) + 1)
	case 28:
		if emptyString {
			return 0
		}
		return net.IPv6len
	default:
		return 0
	}
}
