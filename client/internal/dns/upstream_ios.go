//go:build ios

package dns

import (
	"net"
	"syscall"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func newUpstreamResolver(parentCTX context.Context, interfaceName string, ip net.IP) (*upstreamResolver, error) {
	ctx, cancel := context.WithCancel(parentCTX)

	index, err := getInterfaceIndex(interfaceName)
	if err != nil {
		log.Debugf("unable to get interface index for %s: %s", interfaceName, err)
		return nil, err
	}

	return &upstreamResolver{
		ctx:              ctx,
		cancel:           cancel,
		upstreamTimeout:  upstreamTimeout,
		reactivatePeriod: reactivatePeriod,
		failsTillDeact:   failsTillDeact,
		lIP:              ip,
		iIndex:           index,
	}, nil
}

func (u *upstreamResolver) upstreamExchange(upstream string, r *dns.Msg) (rm *dns.Msg, t time.Duration, err error) {
	client := u.getClientPrivate()
	return client.Exchange(r, upstream)
}

// getClientPrivate returns a new DNS client bound to the local IP address of the Netbird interface
// This method is needed for iOS
func (u *upstreamResolver) getClientPrivate() *dns.Client {
	dialer := &net.Dialer{
		LocalAddr: &net.UDPAddr{
			IP:   u.lIP,
			Port: 0, // Let the OS pick a free port
		},
		Timeout: upstreamTimeout,
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
