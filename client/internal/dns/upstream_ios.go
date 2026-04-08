//go:build ios

package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/peer"
)

type upstreamResolverIOS struct {
	*upstreamResolverBase
	lIP           netip.Addr
	lNet          netip.Prefix
	lIPv6         netip.Addr
	lNetV6        netip.Prefix
	interfaceName string
}

func newUpstreamResolver(
	ctx context.Context,
	wgIface WGIface,
	statusRecorder *peer.Status,
	_ *hostsDNSHolder,
	domain string,
) (*upstreamResolverIOS, error) {
	upstreamResolverBase := newUpstreamResolverBase(ctx, statusRecorder, domain)

	ios := &upstreamResolverIOS{
		upstreamResolverBase: upstreamResolverBase,
		lIP:                  wgIface.Address().IP,
		lNet:                 wgIface.Address().Network,
		lIPv6:                wgIface.Address().IPv6,
		lNetV6:               wgIface.Address().IPv6Net,
		interfaceName:        wgIface.Name(),
	}
	ios.upstreamClient = ios

	return ios, nil
}

func (u *upstreamResolverIOS) exchange(ctx context.Context, upstream string, r *dns.Msg) (rm *dns.Msg, t time.Duration, err error) {
	client := &dns.Client{
		Timeout: ClientTimeout,
	}
	upstreamHost, _, err := net.SplitHostPort(upstream)
	if err != nil {
		return nil, 0, fmt.Errorf("error while parsing upstream host: %s", err)
	}

	timeout := UpstreamTimeout
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	client.DialTimeout = timeout

	upstreamIP, err := netip.ParseAddr(upstreamHost)
	if err != nil {
		log.Warnf("failed to parse upstream host %s: %s", upstreamHost, err)
	} else {
		upstreamIP = upstreamIP.Unmap()
	}
	needsPrivate := u.lNet.Contains(upstreamIP) ||
		u.lNetV6.Contains(upstreamIP) ||
		(u.routeMatch != nil && u.routeMatch(upstreamIP))
	if needsPrivate {
		var bindIP netip.Addr
		switch {
		case upstreamIP.Is6() && u.lIPv6.IsValid():
			bindIP = u.lIPv6
		case upstreamIP.Is4() && u.lIP.IsValid():
			bindIP = u.lIP
		}

		if bindIP.IsValid() {
			log.Debugf("using private client to query %s via upstream %s", r.Question[0].Name, upstream)
			client, err = GetClientPrivate(bindIP, u.interfaceName, timeout)
			if err != nil {
				return nil, 0, fmt.Errorf("create private client: %s", err)
			}
		}
	}

	// Cannot use client.ExchangeContext because it overwrites our Dialer
	return ExchangeWithFallback(nil, client, r, upstream)
}

// GetClientPrivate returns a new DNS client bound to the local IP address of the Netbird interface
// This method is needed for iOS
func GetClientPrivate(ip netip.Addr, interfaceName string, dialTimeout time.Duration) (*dns.Client, error) {
	index, err := getInterfaceIndex(interfaceName)
	if err != nil {
		log.Debugf("unable to get interface index for %s: %s", interfaceName, err)
		return nil, err
	}

	proto, opt := unix.IPPROTO_IP, unix.IP_BOUND_IF
	if ip.Is6() {
		proto, opt = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
	}

	dialer := &net.Dialer{
		LocalAddr: net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, 0)),
		Timeout: dialTimeout,
		Control: func(network, address string, c syscall.RawConn) error {
			var operr error
			fn := func(s uintptr) {
				operr = unix.SetsockoptInt(int(s), proto, opt, index)
			}

			if err := c.Control(fn); err != nil {
				return err
			}

			if operr != nil {
				log.Errorf("error while setting socket option: %s", operr)
			}

			return operr
		},
	}
	client := &dns.Client{
		Dialer:  dialer,
		Timeout: dialTimeout,
	}
	return client, nil
}

func getInterfaceIndex(interfaceName string) (int, error) {
	iface, err := net.InterfaceByName(interfaceName)
	return iface.Index, err
}
