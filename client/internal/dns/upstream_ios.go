//go:build ios

package dns

import (
	"context"
	"fmt"
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
	lIP           net.IP
	lNet          *net.IPNet
	interfaceName string
}

func newUpstreamResolver(
	ctx context.Context,
	interfaceName string,
	ip net.IP,
	net *net.IPNet,
	statusRecorder *peer.Status,
	_ *hostsDNSHolder,
	domain string,
) (*upstreamResolverIOS, error) {
	upstreamResolverBase := newUpstreamResolverBase(ctx, statusRecorder, domain)

	ios := &upstreamResolverIOS{
		upstreamResolverBase: upstreamResolverBase,
		lIP:                  ip,
		lNet:                 net,
		interfaceName:        interfaceName,
	}
	ios.upstreamClient = ios

	return ios, nil
}

func (u *upstreamResolverIOS) exchange(ctx context.Context, upstream string, r *dns.Msg) (rm *dns.Msg, t time.Duration, err error) {
	client := &dns.Client{}
	upstreamHost, _, err := net.SplitHostPort(upstream)
	if err != nil {
		return nil, 0, fmt.Errorf("error while parsing upstream host: %s", err)
	}

	timeout := upstreamTimeout
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}
	client.DialTimeout = timeout

	upstreamIP := net.ParseIP(upstreamHost)
	if u.lNet.Contains(upstreamIP) || net.IP.IsPrivate(upstreamIP) {
		log.Debugf("using private client to query upstream: %s", upstream)
		client, err = GetClientPrivate(u.lIP, u.interfaceName, timeout)
		if err != nil {
			return nil, 0, fmt.Errorf("error while creating private client: %s", err)
		}
	}

	// Cannot use client.ExchangeContext because it overwrites our Dialer
	return client.Exchange(r, upstream)
}

// GetClientPrivate returns a new DNS client bound to the local IP address of the Netbird interface
// This method is needed for iOS
func GetClientPrivate(ip net.IP, interfaceName string, dialTimeout time.Duration) (*dns.Client, error) {
	index, err := getInterfaceIndex(interfaceName)
	if err != nil {
		log.Debugf("unable to get interface index for %s: %s", interfaceName, err)
		return nil, err
	}

	dialer := &net.Dialer{
		LocalAddr: &net.UDPAddr{
			IP:   ip,
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
		Dialer: dialer,
	}
	return client, nil
}

func getInterfaceIndex(interfaceName string) (int, error) {
	iface, err := net.InterfaceByName(interfaceName)
	return iface.Index, err
}
