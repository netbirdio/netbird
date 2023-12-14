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

func newUpstreamResolver(parentCTX context.Context, interfaceName string, ip net.IP, net *net.IPNet) (*upstreamResolverNonIOS, error) {
	upstreamResolverBase := newUpstreamResolverBase(parentCTX)
	nonIOS := &upstreamResolverNonIOS{
		upstreamResolverBase: upstreamResolverBase,
	}
	upstreamResolverBase.upstreamClient = nonIOS
	return nonIOS, nil
}

func (u *upstreamResolverNonIOS) exchange(upstream string, r *dns.Msg) (rm *dns.Msg, t time.Duration, err error) {
	upstreamExchangeClient := &dns.Client{}
	ctx, cancel := context.WithTimeout(u.ctx, u.upstreamTimeout)
	rm, t, err = upstreamExchangeClient.ExchangeContext(ctx, r, upstream)
	cancel()
	return rm, t, err
}
