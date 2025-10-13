//go:build !android && !ios

package dns

import (
	"context"
	"net/netip"
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
	if u.nsNet != nil {
		reply, err := ExchangeWithNetstack(ctx, u.nsNet, r, upstream)
		return reply, 0, err
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
