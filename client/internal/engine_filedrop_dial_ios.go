//go:build ios

package internal

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/filedrop"
)

// fileDropListenControl scopes the receiver's listeners to the tunnel
// interface, so replies on accepted connections leave through the tunnel
// instead of following the Network Extension's own-traffic bypass.
func fileDropListenControl(wgIface WGIface) filedrop.ListenControl {
	return func(network, _ string, c syscall.RawConn) error {
		osIface, err := net.InterfaceByName(wgIface.Name())
		if err != nil {
			return fmt.Errorf("lookup interface %q: %w", wgIface.Name(), err)
		}

		proto, opt := unix.IPPROTO_IP, unix.IP_BOUND_IF
		if strings.HasSuffix(network, "6") {
			proto, opt = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
		}

		var operr error
		if err := c.Control(func(s uintptr) {
			operr = unix.SetsockoptInt(int(s), proto, opt, osIface.Index)
		}); err != nil {
			return err
		}
		return operr
	}
}

// fileDropOSDial scopes the dial to the tunnel interface, since a Network
// Extension's own unscoped sockets bypass its tunnel and leave on the
// physical interface.
func fileDropOSDial(wgIface WGIface) filedrop.DialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		addrPort, err := netip.ParseAddrPort(addr)
		if err != nil {
			return nil, err
		}

		osIface, err := net.InterfaceByName(wgIface.Name())
		if err != nil {
			return nil, fmt.Errorf("lookup interface %q: %w", wgIface.Name(), err)
		}

		wgAddr := wgIface.Address()
		bindIP := wgAddr.IP
		proto, opt := unix.IPPROTO_IP, unix.IP_BOUND_IF
		if addrPort.Addr().Is6() {
			if !wgAddr.HasIPv6() {
				return nil, fmt.Errorf("no IPv6 address on %s", wgIface.Name())
			}
			bindIP = wgAddr.IPv6
			proto, opt = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
		}

		dialer := &net.Dialer{
			LocalAddr: net.TCPAddrFromAddrPort(netip.AddrPortFrom(bindIP, 0)),
			Control: func(_, _ string, c syscall.RawConn) error {
				var operr error
				if err := c.Control(func(s uintptr) {
					operr = unix.SetsockoptInt(int(s), proto, opt, osIface.Index)
				}); err != nil {
					return err
				}
				return operr
			},
		}
		return dialer.DialContext(ctx, network, addr)
	}
}
