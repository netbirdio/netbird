package roundtrip

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

// dialWithDNSResolution wraps a DialContext function so that target addresses
// containing hostnames (rather than IPs) are resolved through NetBird's own
// DNS infrastructure before the connection is dialed.
//
// getDNSAddr is called on every dial that requires hostname resolution; it
// should return the current NetBird DNS server address (IP + port) and true.
// When the DNS server is not yet available it should return false, in which
// case resolution falls back to the process-level default resolver.
//
// The resolver dials the DNS server using the same underlying dial function
// (i.e. through the WireGuard netstack), because in userspace / netstack mode
// the DNS server is reachable only via the virtual WireGuard interface.
func dialWithDNSResolution(
	getDNSAddr func() (netip.AddrPort, bool),
	dial func(ctx context.Context, network, addr string) (net.Conn, error),
) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			// Malformed address — let the underlying dialer handle or fail it.
			return dial(ctx, network, addr)
		}

		// If the host is already an IP literal, skip resolution entirely.
		if _, err := netip.ParseAddr(host); err == nil {
			return dial(ctx, network, addr)
		}

		resolved, err := resolveHost(ctx, host, getDNSAddr, dial)
		if err != nil {
			return nil, err
		}

		return dial(ctx, network, net.JoinHostPort(resolved, port))
	}
}

// resolveHost resolves a hostname to its first IPv4/IPv6 address using a
// custom net.Resolver backed by the NetBird DNS server (when available) or
// the process-level default resolver as a fallback.
func resolveHost(
	ctx context.Context,
	host string,
	getDNSAddr func() (netip.AddrPort, bool),
	dial func(ctx context.Context, network, addr string) (net.Conn, error),
) (string, error) {
	resolver := buildResolver(getDNSAddr, dial)

	addrs, err := resolver.LookupHost(ctx, host)
	if err != nil {
		return "", fmt.Errorf("dns: resolve %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("dns: no addresses returned for %q", host)
	}
	return addrs[0], nil
}

// buildResolver returns a *net.Resolver configured to query the NetBird DNS
// server via the provided dial function.  If the DNS server address is not
// yet available, the default system resolver is returned so that the caller
// can still attempt resolution (useful during client startup).
func buildResolver(
	getDNSAddr func() (netip.AddrPort, bool),
	dial func(ctx context.Context, network, addr string) (net.Conn, error),
) *net.Resolver {
	dnsAddr, ok := getDNSAddr()
	if !ok {
		return net.DefaultResolver
	}

	addrStr := dnsAddr.String()
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			// Always use UDP toward the DNS server.  The network and address
			// arguments passed by net.Resolver are intentionally ignored;
			// we route through the WireGuard netstack instead.
			return dial(ctx, "udp", addrStr)
		},
	}
}
