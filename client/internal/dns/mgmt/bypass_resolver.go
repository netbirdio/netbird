package mgmt

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	nbnet "github.com/netbirdio/netbird/client/net"
)

// NewBypassResolver builds a *net.Resolver that sends queries directly to
// the supplied nameservers through a socket that bypasses the NetBird
// overlay interface. This lets the mgmt cache refresh control-plane
// FQDNs (api/signal/relay/stun/turn) even when an exit-node default
// route is installed on the overlay before its peer is live.
//
// Returns nil if nameservers is empty. The caller must not pass
// loopback/overlay IPs (e.g. 127.0.0.1, the overlay listener address);
// those would defeat the purpose of bypassing.
func NewBypassResolver(nameservers []netip.Addr) *net.Resolver {
	if len(nameservers) == 0 {
		return nil
	}

	servers := make([]string, 0, len(nameservers))
	for _, ns := range nameservers {
		if !ns.IsValid() || ns.IsLoopback() || ns.IsUnspecified() {
			continue
		}
		servers = append(servers, netip.AddrPortFrom(ns, 53).String())
	}
	if len(servers) == 0 {
		return nil
	}

	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			nbDialer := nbnet.NewDialer()
			var lastErr error
			for _, ns := range servers {
				conn, err := nbDialer.DialContext(ctx, network, ns)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			if lastErr == nil {
				return nil, fmt.Errorf("no bypass nameservers configured")
			}
			return nil, fmt.Errorf("dial bypass nameservers: %w", lastErr)
		},
	}
}
