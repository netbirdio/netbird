//go:build js

// Non-address record forwarding for the browser client. TinyGo's net package
// implements only LookupNetIP/LookupTXT/LookupSRV (and the latter two are
// "not implemented" stubs), and has no MX, NS, CNAME or PTR lookup at all, so
// there is no host resolver to forward these queries to. Every non-address type
// is answered NODATA, which is what records.go already does for record types
// the host resolver cannot answer.

package resutil

import (
	"context"

	"github.com/miekg/dns"
)

// RecordResolver is the host resolver surface used to forward non-address
// record queries. Under js there is nothing to forward to, so the surface is
// empty and any resolver satisfies it.
type RecordResolver interface{}

// LookupRecords always answers NODATA (empty answer, NOERROR) under js: no
// records, but no NXDOMAIN either, so a routed name is never poisoned for a
// type this build cannot resolve.
func LookupRecords(_ context.Context, _ RecordResolver, _ string, _ uint16, _ uint32) ([]dns.RR, int) {
	return nil, dns.RcodeSuccess
}
