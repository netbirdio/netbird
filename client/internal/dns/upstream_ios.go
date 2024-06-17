//go:build ios

package dns

import (
	"context"
	"net"
	"syscall"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/peer"
)

type upstreamResolverIOS struct {
	*upstreamResolverBase
	lIP    net.IP
	lNet   *net.IPNet
	iIndex int
}

func newUpstreamResolver(
	ctx context.Context,
	interfaceName string,
	ip net.IP,
	net *net.IPNet,
	statusRecorder *peer.Status,
	_ *hostsDNSHolder,
) (*upstreamResolverIOS, error) {
	upstreamResolverBase := newUpstreamResolverBase(ctx, statusRecorder)

	index, err := getInterfaceIndex(interfaceName)
	if err != nil {
		log.Debugf("unable to get interface index for %s: %s", interfaceName, err)
		return nil, err
	}

	ios := &upstreamResolverIOS{
		upstreamResolverBase: upstreamResolverBase,
		lIP:                  ip,
		lNet:                 net,
		iIndex:               index,
	}
	ios.upstreamClient = ios

	return ios, nil
}

func (u *upstreamResolverIOS) exchange(ctx context.Context, upstream string, r *dns.Msg) (rm *dns.Msg, t time.Duration, err error) {
	client := &dns.Client{}
	upstreamHost, _, err := net.SplitHostPort(upstream)
	if err != nil {
		log.Errorf("error while parsing upstream host: %s", err)
	}

	timeout := upstreamTimeout
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	client.DialTimeout = timeout

	upstreamIP := net.ParseIP(upstreamHost)
	if u.lNet.Contains(upstreamIP) || net.IP.IsPrivate(upstreamIP) {
		log.Debugf("using private client to query upstream: %s", upstream)
		client = u.getClientPrivate(timeout)
	}

	// Cannot use client.ExchangeContext because it overwrites our Dialer
	return client.Exchange(r, upstream)
}

// getClientPrivate returns a new DNS client bound to the local IP address of the Netbird interface
// This method is needed for iOS
func (u *upstreamResolverIOS) getClientPrivate(dialTimeout time.Duration) *dns.Client {
	dialer := &net.Dialer{
		LocalAddr: &net.UDPAddr{
			IP:   u.lIP,
			Port: 0, // Let the OS pick a free port
		},
		Timeout: dialTimeout,
		Control: func(network, address string, c syscall.RawConn) error {
			var operr error
			fn := func(s uintptr) {
				operr = unix.SetsockoptInt(int(s), unix.IPPROTO_IP, unix.IP_BOUND_IF, u.iIndex)
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
		Dialer: dialer,
	}
	return client
}

func getInterfaceIndex(interfaceName string) (int, error) {
	iface, err := net.InterfaceByName(interfaceName)
	return iface.Index, err
}
