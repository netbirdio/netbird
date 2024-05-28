package dns

import (
	"context"
	"net"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"github.com/netbirdio/netbird/client/internal/peer"
	nbnet "github.com/netbirdio/netbird/util/net"
)

type upstreamResolver struct {
	*upstreamResolverBase
	hostsDNSHolder *hostsDNSHolder
}

// newUpstreamResolver in Android we need to distinguish the DNS servers to available through VPN or outside of VPN
// In case if the assigned DNS address is available only in the protected network then the resolver will time out at the
// first time, and we need to wait for a while to start to use again the proper DNS resolver.
func newUpstreamResolver(
	ctx context.Context,
	_ string,
	_ net.IP,
	_ *net.IPNet,
	statusRecorder *peer.Status,
	hostsDNSHolder *hostsDNSHolder,
) (*upstreamResolver, error) {
	upstreamResolverBase := newUpstreamResolverBase(ctx, statusRecorder)
	c := &upstreamResolver{
		upstreamResolverBase: upstreamResolverBase,
		hostsDNSHolder:       hostsDNSHolder,
	}
	upstreamResolverBase.upstreamClient = c
	return c, nil
}

// exchange in case of Android if the upstream is a local resolver then we do not need to mark the socket as protected.
// In other case the DNS resolvation goes through the VPN, so we need to force to use the
func (u *upstreamResolver) exchange(ctx context.Context, upstream string, r *dns.Msg) (rm *dns.Msg, t time.Duration, err error) {
	if u.isLocalResolver(upstream) {
		return u.exchangeWithoutVPN(ctx, upstream, r)
	} else {
		return u.exchangeWithinVPN(ctx, upstream, r)
	}
}

func (u *upstreamResolver) exchangeWithinVPN(ctx context.Context, upstream string, r *dns.Msg) (rm *dns.Msg, t time.Duration, err error) {
	upstreamExchangeClient := &dns.Client{}
	return upstreamExchangeClient.ExchangeContext(ctx, r, upstream)
}

// exchangeWithoutVPN protect the UDP socket by Android SDK to avoid to goes through the VPN
func (u *upstreamResolver) exchangeWithoutVPN(ctx context.Context, upstream string, r *dns.Msg) (rm *dns.Msg, t time.Duration, err error) {
	timeout := upstreamTimeout
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	dialTimeout := timeout

	nbDialer := nbnet.NewDialer()

	dialer := &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			return nbDialer.Control(network, address, c)
		},
		Timeout: dialTimeout,
	}

	upstreamExchangeClient := &dns.Client{
		Dialer: dialer,
	}

	return upstreamExchangeClient.Exchange(r, upstream)
}

func (u *upstreamResolver) isLocalResolver(upstream string) bool {
	if u.hostsDNSHolder.isContain(upstream) {
		return true
	}
	return false
}
