//go:build !ios

package dns

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
)

func newUpstreamResolver(parentCTX context.Context, interfaceName string, ip net.IP) (*upstreamResolver, error) {
	ctx, cancel := context.WithCancel(parentCTX)

	return &upstreamResolver{
		ctx:              ctx,
		cancel:           cancel,
		upstreamTimeout:  upstreamTimeout,
		reactivatePeriod: reactivatePeriod,
		failsTillDeact:   failsTillDeact,
	}, nil
}

func (u *upstreamResolver) upstreamExchange(upstream string, r *dns.Msg) (rm *dns.Msg, t time.Duration, err error) {
	upstreamExchangeClient := &dns.Client{}
	ctx, cancel := context.WithTimeout(u.ctx, u.upstreamTimeout)
	rm, t, err = upstreamExchangeClient.ExchangeContext(ctx, r, upstream)
	cancel()
	return rm, t, err
}
