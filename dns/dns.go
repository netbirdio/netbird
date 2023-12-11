// Package dns implement dns types and standard methods and functions
// to parse and normalize dns records and configuration
package dns

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

const (
	// DefaultDNSPort well-known port number
	DefaultDNSPort = 53
	// RootZone is a string representation of the root zone
	RootZone = "."
	// DefaultClass is the class supported by the system
	DefaultClass = "IN"
)

const invalidHostLabel = "[^a-zA-Z0-9-]+"

// Config represents a dns configuration that is exchanged between management and peers
type Config struct {
	// ServiceEnable indicates if the service should be enabled
	ServiceEnable bool
	// NameServerGroups contains a list of nameserver group
	NameServerGroups []*NameServerGroup
	// CustomZones contains a list of custom zone
	CustomZones []CustomZone
}

// CustomZone represents a custom zone to be resolved by the dns server
type CustomZone struct {
	// Domain is the zone's domain
	Domain string
	// Records custom zone records
	Records []SimpleRecord
}

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

var invalidHostMatcher = regexp.MustCompile(invalidHostLabel)

// GetParsedDomainLabel returns a domain label with max 59 characters,
// parsed for old Hosts.txt requirements, and converted to ASCII and lowercase
func GetParsedDomainLabel(name string) (string, error) {
	labels := dns.SplitDomainName(name)
	if len(labels) == 0 {
		return "", fmt.Errorf("got empty label list for name \"%s\"", name)
	}
	rawLabel := labels[0]
	ascii, err := idna.Punycode.ToASCII(rawLabel)
	if err != nil {
		return "", fmt.Errorf("unable to convert host label to ASCII, error: %v", err)
	}

	validHost := strings.ToLower(invalidHostMatcher.ReplaceAllString(ascii, "-"))
	if len(validHost) > 58 {
		validHost = validHost[:59]
	}

	return validHost, nil
}
