//go:build !android && !ios

package dns

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/management/domain"
)

type upstreamResolver struct {
	*upstreamResolverBase
}

func newUpstreamResolver(
	ctx context.Context,
	_ string,
	_ net.IP,
	_ *net.IPNet,
	statusRecorder *peer.Status,
	_ *hostsDNSHolder,
	domain domain.Domain,
) (*upstreamResolver, error) {
	upstreamResolverBase := newUpstreamResolverBase(ctx, statusRecorder, domain)
	nonIOS := &upstreamResolver{
		upstreamResolverBase: upstreamResolverBase,
	}
	upstreamResolverBase.upstreamClient = nonIOS
	return nonIOS, nil
}

func (u *upstreamResolver) exchange(ctx context.Context, upstream string, r *dns.Msg) (rm *dns.Msg, t time.Duration, err error) {
	return ExchangeWithFallback(ctx, &dns.Client{}, r, upstream)
}
