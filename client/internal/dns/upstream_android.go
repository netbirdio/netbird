package dns

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"github.com/netbirdio/netbird/client/internal/peer"
	nbnet "github.com/netbirdio/netbird/client/net"
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
	_ WGIface,
	statusRecorder *peer.Status,
	hostsDNSHolder *hostsDNSHolder,
	domain string,
) (*upstreamResolver, error) {
	upstreamResolverBase := newUpstreamResolverBase(ctx, statusRecorder, domain)
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
	upstreamExchangeClient := &dns.Client{
		Timeout: ClientTimeout,
	}
	return upstreamExchangeClient.ExchangeContext(ctx, r, upstream)
}

// exchangeWithoutVPN protect the UDP socket by Android SDK to avoid to goes through the VPN
func (u *upstreamResolver) exchangeWithoutVPN(ctx context.Context, upstream string, r *dns.Msg) (rm *dns.Msg, t time.Duration, err error) {
	timeout := UpstreamTimeout
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
		Dialer:  dialer,
		Timeout: timeout,
	}

	return upstreamExchangeClient.ExchangeContext(ctx, r, upstream)
}

func (u *upstreamResolver) isLocalResolver(upstream string) bool {
	if addrPort, err := netip.ParseAddrPort(upstream); err == nil {
		return u.hostsDNSHolder.contains(addrPort)
	}
	return false
}

func GetClientPrivate(ip netip.Addr, interfaceName string, dialTimeout time.Duration) (*dns.Client, error) {
	return &dns.Client{
		Timeout: dialTimeout,
		Net:     "udp",
	}, nil
}
