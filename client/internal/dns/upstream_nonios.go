//go:build !ios

package dns

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
)

type upstreamResolverNonIOS struct {
	*upstreamResolverBase
}

func newUpstreamResolver(parentCTX context.Context, interfaceName string, ip net.IP) (*upstreamResolverNonIOS, error) {
	upstreamResolverBase := newUpstreamResolverBase(parentCTX)

	return &upstreamResolverNonIOS{
		upstreamResolverBase: upstreamResolverBase,
	}, nil
}

func (u *upstreamResolverNonIOS) upstreamExchange(upstream string, r *dns.Msg) (rm *dns.Msg, t time.Duration, err error) {
	upstreamExchangeClient := &dns.Client{}
	ctx, cancel := context.WithTimeout(u.ctx, u.upstreamTimeout)
	rm, t, err = upstreamExchangeClient.ExchangeContext(ctx, r, upstream)
	cancel()
	return rm, t, err
}
