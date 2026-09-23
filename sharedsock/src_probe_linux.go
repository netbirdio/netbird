//go:build linux && !android

package sharedsock

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"unsafe"

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
	// fd is -1 while no socket is open. Any failed lookup closes it and the next
	// lookup opens a fresh one, so a socket in an unknown state is never reused.
	fd     int
	closed bool
}

// newSrcProbe opens a probe socket for the given address family.
func newSrcProbe(family int) (*srcProbe, error) {
	fd, err := openProbeSocket(family)
	if err != nil {
		return nil, err
	}
	return &srcProbe{family: family, fd: fd}, nil
}

// resolve returns the source address the kernel would use for a packet to dst.
// It is safe for concurrent use.
func (p *srcProbe) resolve(dst netip.Addr) (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return netip.Addr{}, errProbeClosed
	}

	if p.fd < 0 {
		fd, err := openProbeSocket(p.family)
		if err != nil {
			return netip.Addr{}, err
		}
		p.fd = fd
	}

	src, err := p.lookup(dst)
	if err != nil {
		if closeErr := p.closeFD(); closeErr != nil {
			log.Debugf("failed to close source probe socket: %v", closeErr)
		}
		return netip.Addr{}, err
	}
	return src, nil
}

// lookup runs one route lookup on the open socket. Callers must hold p.mu.
func (p *srcProbe) lookup(dst netip.Addr) (netip.Addr, error) {
	// A connected socket keeps the source address of its first connect and reuses
	// it for later route lookups, so dissolve the association first.
	if err := disconnect(p.fd); err != nil {
		return netip.Addr{}, fmt.Errorf("disconnect probe socket: %w", err)
	}

	if err := unix.Connect(p.fd, probeSockaddr(dst)); err != nil {
		return netip.Addr{}, fmt.Errorf("route lookup for %s: %w", dst, err)
	}

	sa, err := unix.Getsockname(p.fd)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("read probe socket address: %w", err)
	}

	var src netip.Addr
	switch a := sa.(type) {
	case *unix.SockaddrInet4:
		src = netip.AddrFrom4(a.Addr)
	case *unix.SockaddrInet6:
		src = netip.AddrFrom16(a.Addr)
	}
	if !src.IsValid() || src.IsUnspecified() {
		return netip.Addr{}, fmt.Errorf("no source address for %s", dst)
	}
	return src, nil
}

// close releases the socket. Later lookups fail with errProbeClosed.
func (p *srcProbe) close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.closed = true
	return p.closeFD()
}

func (p *srcProbe) closeFD() error {
	if p.fd < 0 {
		return nil
	}
	err := unix.Close(p.fd)
	p.fd = -1
	return err
}

func openProbeSocket(family int) (int, error) {
	fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		return -1, fmt.Errorf("create source probe socket: %w", err)
	}

	if nbnet.AdvancedRouting() {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(nbnet.ControlPlaneMark)); err != nil {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("set SO_MARK on source probe socket: %w", err)
		}
	}
	return fd, nil
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

func probeSockaddr(dst netip.Addr) unix.Sockaddr {
	// Nothing is sent, so the port is arbitrary.
	const port = 9
	if dst.Is4() {
		return &unix.SockaddrInet4{Port: port, Addr: dst.As4()}
	}
	return &unix.SockaddrInet6{Port: port, Addr: dst.As16()}
}
