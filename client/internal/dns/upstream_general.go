//go:build !android && !ios

package dns

import (
	"context"
	"net"
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
	_ net.IP,
	_ *net.IPNet,
	statusRecorder *peer.Status,
	_ *hostsDNSHolder,
) (*upstreamResolver, error) {
	upstreamResolverBase := newUpstreamResolverBase(ctx, statusRecorder)
	nonIOS := &upstreamResolver{
		upstreamResolverBase: upstreamResolverBase,
	}
	upstreamResolverBase.upstreamClient = nonIOS
	return nonIOS, nil
}

func (u *upstreamResolver) exchange(ctx context.Context, upstream string, r *dns.Msg) (rm *dns.Msg, t time.Duration, err error) {
	upstreamExchangeClient := &dns.Client{}
	return upstreamExchangeClient.ExchangeContext(ctx, r, upstream)
}
