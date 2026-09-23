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
	// sock is nil while no socket is open. Any failed lookup closes it and the next
	// lookup opens a fresh one, so a socket in an unknown state is never reused.
	sock   *probeSocket
	closed bool
}

// probeSocket is an open probe socket and the identity it had when it was opened.
type probeSocket struct {
	fd  int
	dev uint64
	ino uint64
}

// newSrcProbe opens a probe socket for the given address family.
func newSrcProbe(family int) (*srcProbe, error) {
	sock, err := openProbeSocket(family)
	if err != nil {
		return nil, err
	}
	return &srcProbe{family: family, sock: sock}, nil
}

// resolve returns the source address the kernel would use for a packet to dst.
// It is safe for concurrent use.
func (p *srcProbe) resolve(dst netip.Addr) (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return netip.Addr{}, errProbeClosed
	}

	if p.sock != nil && !p.sock.owned() {
		// The number no longer refers to our socket and may belong to someone else
		// now, so drop it without closing it.
		log.Debugf("source probe socket was closed elsewhere, opening a new one")
		p.sock = nil
	}

	if p.sock == nil {
		sock, err := openProbeSocket(p.family)
		if err != nil {
			return netip.Addr{}, err
		}
		p.sock = sock
	}

	src, err := p.sock.lookup(dst)
	if err != nil {
		if closeErr := p.closeSocket(); closeErr != nil {
			log.Debugf("failed to close source probe socket: %v", closeErr)
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

// closeSocket closes the socket if the number still refers to it. Callers must hold p.mu.
func (p *srcProbe) closeSocket() error {
	sock := p.sock
	p.sock = nil
	if sock == nil || !sock.owned() {
		return nil
	}
	return unix.Close(sock.fd)
}

// owned reports whether the fd still refers to the socket that was opened. The
// number may have been closed elsewhere and handed out for another file since.
func (s *probeSocket) owned() bool {
	var st unix.Stat_t
	if err := unix.Fstat(s.fd, &st); err != nil {
		return false
	}
	return st.Mode&unix.S_IFMT == unix.S_IFSOCK && uint64(st.Dev) == s.dev && st.Ino == s.ino
}

// lookup runs one route lookup on the socket.
func (s *probeSocket) lookup(dst netip.Addr) (netip.Addr, error) {
	// A connected socket keeps the source address of its first connect and reuses
	// it for later route lookups, so dissolve the association first.
	if err := disconnect(s.fd); err != nil {
		return netip.Addr{}, fmt.Errorf("disconnect probe socket: %w", err)
	}

	if err := unix.Connect(s.fd, probeSockaddr(dst)); err != nil {
		return netip.Addr{}, fmt.Errorf("route lookup for %s: %w", dst, err)
	}

	sa, err := unix.Getsockname(s.fd)
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

func openProbeSocket(family int) (*probeSocket, error) {
	fd, err := unix.Socket(family, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		return nil, fmt.Errorf("create source probe socket: %w", err)
	}

	if nbnet.AdvancedRouting() {
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, int(nbnet.ControlPlaneMark)); err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("set SO_MARK on source probe socket: %w", err)
		}
	}

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("stat source probe socket: %w", err)
	}
	return &probeSocket{fd: fd, dev: uint64(st.Dev), ino: st.Ino}, nil
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
