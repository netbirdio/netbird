//go:build js

package dnsfwd

import (
	"context"
	"net/netip"
)

// resolver is the host resolver surface the forwarder needs. TinyGo's net
// package implements only LookupNetIP; it has no MX, NS, SRV, TXT, CNAME or
// PTR lookup, so the js build resolves addresses only and answers every other
// record type NODATA (see resutil.LookupRecords in records_js.go).
type resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}
