// Package resutil provides shared DNS resolution utilities
package resutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

// GenerateRequestID creates a random 8-character hex string for request tracing.
func GenerateRequestID() string {
	bytes := make([]byte, 4)
	if _, err := rand.Read(bytes); err != nil {
		log.Errorf("generate request ID: %v", err)
		return ""
	}
	return hex.EncodeToString(bytes)
}

// IPsToRRs converts a slice of IP addresses to DNS resource records.
// IPv4 addresses become A records, IPv6 addresses become AAAA records.
func IPsToRRs(name string, ips []netip.Addr, ttl uint32) []dns.RR {
	var result []dns.RR

	for _, ip := range ips {
		if ip.Is6() {
			result = append(result, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    ttl,
				},
				AAAA: ip.AsSlice(),
			})
		} else {
			result = append(result, &dns.A{
				Hdr: dns.RR_Header{
					Name:   name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    ttl,
				},
				A: ip.AsSlice(),
			})
		}
	}

	return result
}

// NetworkForQtype returns the network string ("ip4" or "ip6") for a DNS query type.
// Returns empty string for unsupported types.
func NetworkForQtype(qtype uint16) string {
	switch qtype {
	case dns.TypeA:
		return "ip4"
	case dns.TypeAAAA:
		return "ip6"
	default:
		return ""
	}
}

type resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// chainedWriter is implemented by ResponseWriters that carry request metadata
type chainedWriter interface {
	RequestID() string
	SetMeta(key, value string)
}

// GetRequestID extracts a request ID from the ResponseWriter if available,
// otherwise generates a new one.
func GetRequestID(w dns.ResponseWriter) string {
	if cw, ok := w.(chainedWriter); ok {
		if id := cw.RequestID(); id != "" {
			return id
		}
	}
	return GenerateRequestID()
}

// SetMeta sets metadata on the ResponseWriter if it supports it.
func SetMeta(w dns.ResponseWriter, key, value string) {
	if cw, ok := w.(chainedWriter); ok {
		cw.SetMeta(key, value)
	}
}

// LookupResult contains the result of an external DNS lookup
type LookupResult struct {
	IPs   []netip.Addr
	Rcode int
	Err   error // Original error for caller's logging needs
}

// LookupIP performs a DNS lookup and determines the appropriate rcode.
func LookupIP(ctx context.Context, r resolver, network, host string, qtype uint16) LookupResult {
	ips, err := r.LookupNetIP(ctx, network, host)
	if err != nil {
		return LookupResult{
			Rcode: getRcodeForError(ctx, r, host, qtype, err),
			Err:   err,
		}
	}

	// Unmap IPv4-mapped IPv6 addresses that some resolvers may return
	for i, ip := range ips {
		ips[i] = ip.Unmap()
	}

	return LookupResult{
		IPs:   ips,
		Rcode: dns.RcodeSuccess,
	}
}

func getRcodeForError(ctx context.Context, r resolver, host string, qtype uint16, err error) int {
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		return dns.RcodeServerFailure
	}

	if dnsErr.IsNotFound {
		return getRcodeForNotFound(ctx, r, host, qtype)
	}

	return dns.RcodeServerFailure
}

// getRcodeForNotFound distinguishes between NXDOMAIN (domain doesn't exist) and NODATA
// (domain exists but no records of requested type) by checking the opposite record type.
//
// musl libc (the reason we need this distinction) only queries A/AAAA pairs in getaddrinfo,
// so checking the opposite A/AAAA type is sufficient. Other record types (MX, TXT, etc.)
// are not queried by musl and don't need this handling.
func getRcodeForNotFound(ctx context.Context, r resolver, domain string, originalQtype uint16) int {
	// Try querying for a different record type to see if the domain exists
	// If the original query was for AAAA, try A. If it was for A, try AAAA.
	// This helps distinguish between NXDOMAIN and NODATA.
	var alternativeNetwork string
	switch originalQtype {
	case dns.TypeAAAA:
		alternativeNetwork = "ip4"
	case dns.TypeA:
		alternativeNetwork = "ip6"
	default:
		return dns.RcodeNameError
	}

	if _, err := r.LookupNetIP(ctx, alternativeNetwork, domain); err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			// Alternative query also returned not found - domain truly doesn't exist
			return dns.RcodeNameError
		}
		// Some other error (timeout, server failure, etc.) - can't determine, assume domain exists
		return dns.RcodeSuccess
	}

	// Alternative query succeeded - domain exists but has no records of this type
	return dns.RcodeSuccess
}

// FormatAnswers formats DNS resource records for logging.
func FormatAnswers(answers []dns.RR) string {
	if len(answers) == 0 {
		return "[]"
	}

	parts := make([]string, 0, len(answers))
	for _, rr := range answers {
		switch r := rr.(type) {
		case *dns.A:
			parts = append(parts, r.A.String())
		case *dns.AAAA:
			parts = append(parts, r.AAAA.String())
		case *dns.CNAME:
			parts = append(parts, "CNAME:"+r.Target)
		case *dns.PTR:
			parts = append(parts, "PTR:"+r.Ptr)
		default:
			parts = append(parts, dns.TypeToString[rr.Header().Rrtype])
		}
	}
	return "[" + strings.Join(parts, ", ") + "]"
}
