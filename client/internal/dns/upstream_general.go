//go:build !android && !ios

package dns

import (
	"context"
	"net/netip"
	"runtime"
	"time"

	"github.com/miekg/dns"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/netbirdio/netbird/client/internal/peer"
)

type upstreamResolver struct {
	*upstreamResolverBase
	nsNet *netstack.Net
}

func newUpstreamResolver(
	ctx context.Context,
	wgIface WGIface,
	statusRecorder *peer.Status,
	_ *hostsDNSHolder,
	domain string,
) (*upstreamResolver, error) {
	upstreamResolverBase := newUpstreamResolverBase(ctx, statusRecorder, domain)
	nonIOS := &upstreamResolver{
		upstreamResolverBase: upstreamResolverBase,
		nsNet:                wgIface.GetNet(),
	}
	upstreamResolverBase.upstreamClient = nonIOS
	return nonIOS, nil
}

func (u *upstreamResolver) exchange(ctx context.Context, upstream string, r *dns.Msg) (rm *dns.Msg, t time.Duration, err error) {
	// TODO: Check if upstream DNS server is routed through a peer before using netstack.
	// Similar to iOS logic, we should determine if the DNS server is reachable directly
	// or needs to go through the tunnel, and only use netstack when necessary.
	// For now, only use netstack on JS platform where direct access is not possible.
	if u.nsNet != nil && runtime.GOOS == "js" {
		start := time.Now()
		reply, err := ExchangeWithNetstack(ctx, u.nsNet, r, upstream)
		return reply, time.Since(start), err
	}

	client := &dns.Client{
		Timeout: ClientTimeout,
	}
	return ExchangeWithFallback(ctx, client, r, upstream)
}

func GetClientPrivate(ip netip.Addr, interfaceName string, dialTimeout time.Duration) (*dns.Client, error) {
	return &dns.Client{
		Timeout: dialTimeout,
		Net:     "udp",
	}, nil
}
