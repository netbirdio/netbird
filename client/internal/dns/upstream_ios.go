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
	if u.lNet.Contains(upstreamIP) || upstreamIP.IsPrivate() {
		log.Debugf("using private client to query upstream: %s", upstream)
		client, err = GetClientPrivate(u.lIP, u.interfaceName, timeout)
		if err != nil {
			return nil, 0, fmt.Errorf("error while creating private client: %s", err)
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

	dialer := &net.Dialer{
		LocalAddr: &net.UDPAddr{
			IP:   ip.AsSlice(),
			Port: 0, // Let the OS pick a free port
		},
		Timeout: dialTimeout,
		Control: func(network, address string, c syscall.RawConn) error {
			var operr error
			fn := func(s uintptr) {
				operr = unix.SetsockoptInt(int(s), unix.IPPROTO_IP, unix.IP_BOUND_IF, index)
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
