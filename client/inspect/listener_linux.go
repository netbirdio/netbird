package inspect

import (
	"fmt"
	"net"
	"net/netip"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// newTPROXYListener creates a TCP listener for the transparent proxy.
// After nftables REDIRECT, accepted connections have LocalAddr = WG_IP:proxy_port.
// The original destination is retrieved via getsockopt(SO_ORIGINAL_DST).
func newTPROXYListener(logger *log.Entry, addr netip.AddrPort, _ netip.Prefix) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr.String())
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", addr, err)
	}

	logger.Infof("inspect: listener started on %s", ln.Addr())
	return ln, nil
}

// getOriginalDst reads the original destination from conntrack via SO_ORIGINAL_DST.
// This is set by the kernel when the connection was REDIRECT'd/DNAT'd.
// Tries IPv4 first, then falls back to IPv6 (IP6T_SO_ORIGINAL_DST).
func getOriginalDst(conn net.Conn) (netip.AddrPort, error) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("not a TCPConn")
	}

	raw, err := tc.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("get syscall conn: %w", err)
	}

	var origDst netip.AddrPort
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		// Try IPv4 first (SO_ORIGINAL_DST = 80)
		var sa4 unix.RawSockaddrInet4
		sa4Len := uint32(unsafe.Sizeof(sa4))
		_, _, errno := unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			fd,
			unix.SOL_IP,
			80, // SO_ORIGINAL_DST
			uintptr(unsafe.Pointer(&sa4)),
			uintptr(unsafe.Pointer(&sa4Len)),
			0,
		)
		if errno == 0 {
			addr := netip.AddrFrom4(sa4.Addr)
			port := uint16(sa4.Port>>8) | uint16(sa4.Port<<8)
			origDst = netip.AddrPortFrom(addr.Unmap(), port)
			return
		}

		// Fall back to IPv6 (IP6T_SO_ORIGINAL_DST = 80 on SOL_IPV6)
		var sa6 unix.RawSockaddrInet6
		sa6Len := uint32(unsafe.Sizeof(sa6))
		_, _, errno = unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			fd,
			unix.SOL_IPV6,
			80, // IP6T_SO_ORIGINAL_DST
			uintptr(unsafe.Pointer(&sa6)),
			uintptr(unsafe.Pointer(&sa6Len)),
			0,
		)
		if errno != 0 {
			sockErr = fmt.Errorf("getsockopt SO_ORIGINAL_DST (v4 and v6): %w", errno)
			return
		}
		addr := netip.AddrFrom16(sa6.Addr)
		port := uint16(sa6.Port>>8) | uint16(sa6.Port<<8)
		origDst = netip.AddrPortFrom(addr.Unmap(), port)
	}); err != nil {
		return netip.AddrPort{}, fmt.Errorf("control raw conn: %w", err)
	}
	if sockErr != nil {
		return netip.AddrPort{}, sockErr
	}

	return origDst, nil
}
