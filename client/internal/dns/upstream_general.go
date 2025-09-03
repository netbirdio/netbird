//go:build !android && !ios

package dns

import (
	"context"
	"net/netip"
	"time"

	"github.com/miekg/dns"

	"github.com/netbirdio/netbird/client/internal/peer"
)

type upstreamResolver struct {
	*upstreamResolverBase
}

func newUpstreamResolver(
	ctx context.Context,
	_ string,
	_ netip.Addr,
	_ netip.Prefix,
	statusRecorder *peer.Status,
	_ *hostsDNSHolder,
	domain string,
) (*upstreamResolver, error) {
	upstreamResolverBase := newUpstreamResolverBase(ctx, statusRecorder, domain)
	nonIOS := &upstreamResolver{
		upstreamResolverBase: upstreamResolverBase,
	}
	upstreamResolverBase.upstreamClient = nonIOS
	return nonIOS, nil
}

func (u *upstreamResolver) exchange(ctx context.Context, upstream string, r *dns.Msg) (rm *dns.Msg, t time.Duration, err error) {
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
