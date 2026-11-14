//go:build !js

package dnsfwd

import (
	"context"
	"net"
	"net/netip"
)

// resolver is the host resolver surface the forwarder needs.
// net.DefaultResolver satisfies it, and it must also satisfy
// resutil.RecordResolver so non-address queries can be forwarded.
type resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}
