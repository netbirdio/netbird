//go:build !ios

package dns

import (
	"context"
	"time"

	"github.com/miekg/dns"
)

func (u *upstreamResolver) upstreamExchange(upstream string, r *dns.Msg) (rm *dns.Msg, t time.Duration, err error) {
	upstreamExchangeClient := &dns.Client{}
	ctx, cancel := context.WithTimeout(u.ctx, u.upstreamTimeout)
	rm, t, err = upstreamExchangeClient.ExchangeContext(ctx, r, upstream)
	cancel()
	return rm, t, err
}
