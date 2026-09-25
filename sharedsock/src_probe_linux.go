//go:build linux && !android

package sharedsock

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	"github.com/mdlayher/socket"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	nbnet "github.com/netbirdio/netbird/client/net"
)

var errProbeClosed = errors.New("source probe closed")

// srcProbe finds the source address the kernel picks for a destination by connecting
// a UDP socket that carries the raw sockets' fwmark and reading back its local address.
// Connecting a UDP socket runs the output route lookup without sending anything.
type srcProbe struct {
	family int

	mu sync.Mutex
	// conn is nil while no socket is open. A failed route lookup keeps the socket,
	// any other failure closes it and the next lookup opens a fresh one, so a socket
	// in an unknown state is never reused.
	conn   *socket.Conn
	closed bool
}

// newSrcProbe opens a probe socket for the given address family.
func newSrcProbe(family int) (*srcProbe, error) {
	conn, err := openProbeSocket(family)
	if err != nil {
		return nil, err
	}
	return &srcProbe{family: family, conn: conn}, nil
}

// resolve returns the source address the kernel would use for a packet to sa, a
// sockaddr of the probe's family. It is safe for concurrent use.
func (p *srcProbe) resolve(sa unix.Sockaddr) (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return netip.Addr{}, errProbeClosed
	}

	if p.conn == nil {
		conn, err := openProbeSocket(p.family)
		if err != nil {
			return netip.Addr{}, err
		}
		p.conn = conn
	}

	src, err := p.lookup(sa)
	if err != nil {
		var rErr *routeError
		if !errors.As(err, &rErr) {
			if closeErr := p.closeSocket(); closeErr != nil {
				log.Debugf("failed to close source probe socket: %v", closeErr)
			}
		}
		return netip.Addr{}, err
	}
	return src, nil
}

// close releases the socket. Later lookups fail with errProbeClosed.
func (p *srcProbe) close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.closed = true
	return p.closeSocket()
}

// closeSocket closes the socket if one is open. Callers must hold p.mu.
func (p *srcProbe) closeSocket() error {
	conn := p.conn
	p.conn = nil
	if conn == nil {
		return nil
	}
	return conn.Close()
}

// lookup runs one route lookup on the socket. Callers must hold p.mu.
func (p *srcProbe) lookup(sa unix.Sockaddr) (netip.Addr, error) {
	rc, err := p.conn.SyscallConn()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("probe socket: %w", err)
	}

	var src netip.Addr
	var lookupErr error
	if err := rc.Control(func(fd uintptr) {
		src, lookupErr = lookupFD(int(fd), sa)
	}); err != nil {
		return netip.Addr{}, fmt.Errorf("probe socket: %w", err)
	}
	return src, lookupErr
}

// routeError is a route lookup the kernel refused. The socket is still usable after it.
type routeError struct {
	err error
}

func (e *routeError) Error() string {
	return fmt.Sprintf("route lookup: %v", e.err)
}

func (e *routeError) Unwrap() error {
	return e.err
}

func lookupFD(fd int, sa unix.Sockaddr) (netip.Addr, error) {
	// A connected socket keeps the source address of its first connect and reuses
	// it for later route lookups, so dissolve the association first.
	if err := disconnect(fd); err != nil {
		return netip.Addr{}, fmt.Errorf("disconnect probe socket: %w", err)
	}

	if err := unix.Connect(fd, sa); err != nil {
		return netip.Addr{}, &routeError{err: err}
	}

	local, err := unix.Getsockname(fd)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("read probe socket address: %w", err)
	}

	var src netip.Addr
	switch a := local.(type) {
	case *unix.SockaddrInet4:
		src = netip.AddrFrom4(a.Addr)
	case *unix.SockaddrInet6:
		src = netip.AddrFrom16(a.Addr)
	}
	if !src.IsValid() || src.IsUnspecified() {
		return netip.Addr{}, &routeError{err: errors.New("no source address")}
	}
	return src, nil
}

func openProbeSocket(family int) (*socket.Conn, error) {
	conn, err := socket.Socket(family, unix.SOCK_DGRAM, unix.IPPROTO_UDP, "udp_src_probe", nil)
	if err != nil {
		return nil, fmt.Errorf("create source probe socket: %w", err)
	}

	if err := nbnet.SetSocketMark(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("set SO_MARK on source probe socket: %w", err)
	}
	return conn, nil
}

// disconnect dissolves a UDP socket's association by connecting to AF_UNSPEC, which
// also clears the source address the kernel pinned on the previous connect.
func disconnect(fd int) error {
	sa := unix.RawSockaddr{Family: unix.AF_UNSPEC}
	_, _, errno := unix.Syscall(unix.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&sa)), unsafe.Sizeof(sa))
	if errno != 0 {
		return errno
	}
	return nil
}

// rawSockaddr returns the sockaddr for dst with port 0 and the given scope. Port 0
// matches a raw send, whose route lookup carries no ports. A UDP probe connected
// to it still gets an ephemeral source port before its lookup.
func rawSockaddr(dst netip.Addr, scope uint32) unix.Sockaddr {
	if dst.Is4() {
		return &unix.SockaddrInet4{Addr: dst.As4()}
	}
	return &unix.SockaddrInet6{Addr: dst.As16(), ZoneId: scope}
}

// zoneIndex returns the interface index for an IPv6 zone, which is either an
// interface name or a numeric index. An empty zone is index 0. A name costs one
// SIOCGIFINDEX ioctl on rc, which may be any socket.
func zoneIndex(rc syscall.RawConn, zone string) (uint32, error) {
	if zone == "" {
		return 0, nil
	}
	if idx, err := strconv.ParseUint(zone, 10, 32); err == nil {
		return uint32(idx), nil
	}

	ifr, err := unix.NewIfreq(zone)
	if err != nil {
		return 0, fmt.Errorf("zone %q: %w", zone, err)
	}
	var ioctlErr error
	if err := rc.Control(func(fd uintptr) {
		ioctlErr = unix.IoctlIfreq(int(fd), unix.SIOCGIFINDEX, ifr)
	}); err != nil {
		return 0, fmt.Errorf("zone %q: %w", zone, err)
	}
	if ioctlErr != nil {
		return 0, fmt.Errorf("resolve zone %q: %w", zone, ioctlErr)
	}
	return ifr.Uint32(), nil
}
