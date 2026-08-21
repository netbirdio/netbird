// Package gonetfake is an in-process network standing in for the netdev TinyGo's
// net package expects. It lives here rather than in lneto so it can be exercised
// against a real client first; the intent is to fold it back into lneto's
// x/netdev once it has earned its place there.
package gonetfake

import (
	"errors"
	"io"
	"net/netip"
	"sync"
	"time"

	"github.com/soypat/lneto/x/netdev"
)

// Socket domains, types, protocols and options as TinyGo's net passes them to a
// [netdev.GoNet]. Values are the Berkeley ones, mirroring TinyGo's net/netdev.go.
const (
	_AF_INET       = 0x2
	_SOCK_STREAM   = 0x1
	_SOCK_DGRAM    = 0x2
	_SOL_SOCKET    = 0x1
	_SO_KEEPALIVE  = 0x9
	_SO_LINGER     = 0xd
	_SOL_TCP       = 0x6
	_TCP_KEEPINTVL = 0x5
	_IPPROTO_TCP   = 0x6
	_IPPROTO_UDP   = 0x11
)

// Errors returned by [GoNetFake], standing in for the errno values a kernel
// netdev returns. TinyGo's net wraps whatever comes back in an OpError.
var (
	ErrBadFD        = errors.New("netdev: bad file descriptor")
	ErrAddrInUse    = errors.New("netdev: address already in use")
	ErrAlreadyBound = errors.New("netdev: socket already bound")
	ErrConnRefused  = errors.New("netdev: connection refused")
	ErrConnReset    = errors.New("netdev: connection reset by peer")
	ErrNotConnected = errors.New("netdev: socket not connected")
	ErrIsConnected  = errors.New("netdev: socket already connected")
	ErrNotListening = errors.New("netdev: socket not listening")
	ErrSockClosed   = errors.New("netdev: use of closed socket")
	ErrNoPorts      = errors.New("netdev: no ephemeral ports available")
	ErrSockType     = errors.New("netdev: unsupported socket domain, type or protocol")
)

// ErrTimeout is returned when a Send or Recv deadline expires. It satisfies
// net.Error, so callers branching on Timeout() — gRPC, net/http — see a timeout.
var ErrTimeout error = timeoutError{}

type timeoutError struct{}

func (timeoutError) Error() string   { return "netdev: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type hostNotFoundError struct{ name string }

func (e *hostNotFoundError) Error() string { return "netdev: no such host: " + e.name }

// firstFD skips the three descriptors reserved for standard streams, so a
// socket number is never one of them nor the -1 that signals failure.
const firstFD = 3

const (
	ephemeralFirst = 49152
	ephemeralLast  = 65535
)

// defaultQueueBytes caps unread data before a sender blocks. Unbounded, a
// stalled reader grows the queue until memory runs out, taking the tab with it.
const defaultQueueBytes = 65535

// GoNetFake is an in-process network implementing [netdev.GoNet]. Sockets reach
// other sockets in the same program and nothing else, like the fake network the
// Go standard library compiles for GOOS=js (net_fake.go).
//
// It exists so a wasm or baremetal build has a netdev at all: until one is
// installed with [netdev.UseNetdev], every net call fails with ErrNetdevNotSet. This
// makes listening, dialling and the ephemeral-port dance work; it does not make
// packets leave the program. For that, set [GoNetFake.Dial].
//
// The zero value is ready to use. It is safe for concurrent use.
type GoNetFake struct {
	// HostAddr is the address this host answers to, and what an unspecified
	// bind is rewritten to. Zero means 127.0.0.1.
	HostAddr netip.Addr

	// Hosts resolves names for GetHostByName that are not address literals.
	// Absent names do not resolve; there is no upstream resolver to fall to.
	Hosts map[string]netip.Addr

	// Dial, when non-nil, supplies the far end of a Connect whose destination
	// no local socket is bound to, so a real transport can attach here. For a
	// datagram socket one Write is one datagram, one Read is one datagram.
	//
	// A conn also implementing SetReadDeadline and SetWriteDeadline has Recv
	// and Send deadlines applied to it; otherwise those calls block on it.
	Dial func(stype int, host string, raddr netip.AddrPort) (io.ReadWriteCloser, error)

	mu       sync.Mutex
	socks    map[int]*fakeSock
	bound    map[netip.AddrPort]*fakeSock
	nextFD   int
	nextPort int
}

var _ netdev.GoNet = (*GoNetFake)(nil)

// deadlineConn is the optional half of [GoNetFake.Dial]'s contract: a conn
// interruptible on a schedule rather than only by being closed.
type deadlineConn interface {
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// fakeSock is one socket. Every field is guarded by the owning GoNetFake's
// mutex except closed and rx, which synchronise themselves so Recv can block.
type fakeSock struct {
	fd    int
	stype int

	closed    chan struct{}
	closeOnce sync.Once

	laddr     netip.AddrPort
	raddr     netip.AddrPort
	bound     bool
	listening bool
	connected bool

	// backlog carries connections accepted by the network but not yet by the
	// program. Non-nil only once Listen has run.
	backlog chan *fakeSock

	// rx holds what this socket was sent. Listeners never read theirs.
	rx *sockQueue

	// peer is where this socket sends. Mutual for a stream pair, one-way for a
	// datagram socket; nil once connected means sends are discarded.
	peer *fakeSock

	// ext is the far end when [GoNetFake.Dial] supplied it, exclusive with peer.
	ext    io.ReadWriteCloser
	extDdl deadlineConn
}

func (gn *GoNetFake) initLocked() {
	if gn.socks == nil {
		gn.socks = make(map[int]*fakeSock)
		gn.bound = make(map[netip.AddrPort]*fakeSock)
		gn.nextFD = firstFD
		gn.nextPort = ephemeralFirst
	}
}

func (gn *GoNetFake) hostAddr() netip.Addr {
	if gn.HostAddr.IsValid() {
		return gn.HostAddr.Unmap()
	}
	return netip.AddrFrom4([4]byte{127, 0, 0, 1})
}

func (gn *GoNetFake) sockLocked(fd int) (*fakeSock, error) {
	gn.initLocked()
	s := gn.socks[fd]
	if s == nil {
		return nil, ErrBadFD
	}
	return s, nil
}

// Addr returns the address this host answers to.
func (gn *GoNetFake) Addr() (netip.Addr, error) {
	gn.mu.Lock()
	defer gn.mu.Unlock()
	return gn.hostAddr(), nil
}

// GetHostByName resolves an address literal or a name in [GoNetFake.Hosts].
// Anything else fails: a fake network has no resolver.
func (gn *GoNetFake) GetHostByName(name string) (netip.Addr, error) {
	if addr, err := netip.ParseAddr(name); err == nil {
		return addr.Unmap(), nil
	}
	gn.mu.Lock()
	addr, ok := gn.Hosts[name]
	gn.mu.Unlock()
	if ok && addr.IsValid() {
		return addr.Unmap(), nil
	}
	return netip.Addr{}, &hostNotFoundError{name: name}
}

// Socket allocates a descriptor. Only IPv4 stream and datagram sockets exist
// here, which is all TinyGo's net asks for.
func (gn *GoNetFake) Socket(domain, stype, protocol int) (int, error) {
	if domain != _AF_INET {
		return -1, ErrSockType
	}
	switch stype {
	case _SOCK_STREAM:
		if protocol != 0 && protocol != _IPPROTO_TCP {
			return -1, ErrSockType
		}
	case _SOCK_DGRAM:
		if protocol != 0 && protocol != _IPPROTO_UDP {
			return -1, ErrSockType
		}
	default:
		return -1, ErrSockType
	}

	gn.mu.Lock()
	defer gn.mu.Unlock()
	gn.initLocked()
	s := &fakeSock{
		fd:     gn.nextFD,
		stype:  stype,
		closed: make(chan struct{}),
		rx:     newSockQueue(stype == _SOCK_STREAM, defaultQueueBytes),
	}
	gn.nextFD++
	gn.socks[s.fd] = s
	return s.fd, nil
}

// Bind assigns a local address. An unspecified address becomes
// [GoNetFake.HostAddr]; port 0 draws from the ephemeral range.
func (gn *GoNetFake) Bind(sockfd int, ip netip.AddrPort) error {
	gn.mu.Lock()
	defer gn.mu.Unlock()
	s, err := gn.sockLocked(sockfd)
	if err != nil {
		return err
	}
	if s.bound {
		return ErrAlreadyBound
	}
	return gn.bindLocked(s, ip)
}

func (gn *GoNetFake) bindLocked(s *fakeSock, ip netip.AddrPort) error {
	addr := ip.Addr().Unmap()
	if !addr.IsValid() || addr.IsUnspecified() {
		addr = gn.hostAddr()
	}
	port := ip.Port()
	if port == 0 {
		p, err := gn.allocPortLocked(addr)
		if err != nil {
			return err
		}
		port = p
	} else if _, dup := gn.bound[netip.AddrPortFrom(addr, port)]; dup {
		return ErrAddrInUse
	}
	s.laddr = netip.AddrPortFrom(addr, port)
	s.bound = true
	gn.bound[s.laddr] = s
	return nil
}

// allocPortLocked resumes where the last allocation stopped, so consecutive
// binds differ without rescanning. It wraps once, then gives up.
func (gn *GoNetFake) allocPortLocked(addr netip.Addr) (uint16, error) {
	for range ephemeralLast - ephemeralFirst + 1 {
		port := uint16(gn.nextPort)
		gn.nextPort++
		if gn.nextPort > ephemeralLast {
			gn.nextPort = ephemeralFirst
		}
		if _, taken := gn.bound[netip.AddrPortFrom(addr, port)]; !taken {
			return port, nil
		}
	}
	return 0, ErrNoPorts
}

// Listen marks a bound stream socket as accepting. An unbound socket is bound
// to an ephemeral port first, as listen(2) does.
func (gn *GoNetFake) Listen(sockfd, backlog int) error {
	gn.mu.Lock()
	defer gn.mu.Unlock()
	s, err := gn.sockLocked(sockfd)
	if err != nil {
		return err
	}
	if s.stype != _SOCK_STREAM {
		return ErrSockType
	}
	if s.connected {
		return ErrIsConnected
	}
	if !s.bound {
		if err := gn.bindLocked(s, netip.AddrPort{}); err != nil {
			return err
		}
	}
	if backlog < 1 {
		backlog = 1
	}
	s.listening = true
	s.backlog = make(chan *fakeSock, backlog)
	return nil
}

// Accept blocks until a connection arrives or the listener closes. It takes no
// deadline: TCPListener.SetDeadline in TinyGo's net is a documented no-op.
func (gn *GoNetFake) Accept(sockfd int) (int, netip.AddrPort, error) {
	gn.mu.Lock()
	s, err := gn.sockLocked(sockfd)
	if err == nil && !s.listening {
		err = ErrNotListening
	}
	gn.mu.Unlock()
	if err != nil {
		return -1, netip.AddrPort{}, err
	}

	select {
	case srv := <-s.backlog:
		return srv.fd, srv.raddr, nil
	case <-s.closed:
		return -1, netip.AddrPort{}, ErrSockClosed
	}
}

// Connect points a socket at a destination: a local socket bound to exactly
// that address, else [GoNetFake.Dial], else refused for a stream and a black
// hole for a datagram — the asymmetry a kernel shows, UDP having none to refuse.
//
// Reaching a local socket means addressing it as bound, which after Bind's
// rewriting is [GoNetFake.HostAddr]. Every other destination belongs to Dial.
func (gn *GoNetFake) Connect(sockfd int, host string, ip netip.AddrPort) error {
	gn.mu.Lock()
	s, err := gn.sockLocked(sockfd)
	if err == nil {
		switch {
		case s.listening:
			err = ErrNotConnected
		case s.connected:
			err = ErrIsConnected
		case !ip.IsValid():
			err = ErrConnRefused
		}
	}
	if err != nil {
		gn.mu.Unlock()
		return err
	}
	if !s.bound {
		if err := gn.bindLocked(s, netip.AddrPort{}); err != nil {
			gn.mu.Unlock()
			return err
		}
	}

	dst := gn.bound[netip.AddrPortFrom(ip.Addr().Unmap(), ip.Port())]
	if dst != nil {
		err := gn.connectLocalLocked(s, dst, ip)
		gn.mu.Unlock()
		return err
	}
	dial := gn.Dial
	stype := s.stype
	gn.mu.Unlock()

	if dial == nil {
		if stype == _SOCK_STREAM {
			return ErrConnRefused
		}
		// A datagram socket aimed at nothing is still a usable socket.
		gn.mu.Lock()
		s.raddr = ip
		s.connected = true
		gn.mu.Unlock()
		return nil
	}

	rwc, err := dial(stype, host, ip)
	if err != nil {
		return err
	}
	gn.mu.Lock()
	s.ext = rwc
	s.extDdl, _ = rwc.(deadlineConn)
	s.raddr = ip
	s.connected = true
	gn.mu.Unlock()
	return nil
}

func (gn *GoNetFake) connectLocalLocked(s, dst *fakeSock, ip netip.AddrPort) error {
	if s.stype == _SOCK_DGRAM {
		// One-way on purpose: dst may be connected elsewhere, and an
		// unconnected datagram socket still receives.
		if dst.stype != _SOCK_DGRAM {
			return ErrConnRefused
		}
		s.peer = dst
		s.raddr = ip
		s.connected = true
		return nil
	}

	if !dst.listening {
		return ErrConnRefused
	}
	srv := &fakeSock{
		fd:        gn.nextFD,
		stype:     _SOCK_STREAM,
		closed:    make(chan struct{}),
		rx:        newSockQueue(true, defaultQueueBytes),
		laddr:     dst.laddr,
		raddr:     s.laddr,
		connected: true,
		peer:      s,
	}
	gn.nextFD++

	select {
	case dst.backlog <- srv:
	default:
		// Backlog full. Refusing beats blocking with the mutex held.
		return ErrConnRefused
	}
	gn.socks[srv.fd] = srv
	s.peer = srv
	s.raddr = ip
	s.connected = true
	return nil
}

// Send writes to the connected peer. flags are ignored; this network
// understands none.
func (gn *GoNetFake) Send(sockfd int, buf []byte, flags int, deadline time.Time) (int, error) {
	gn.mu.Lock()
	s, err := gn.sockLocked(sockfd)
	if err == nil && !s.connected {
		err = ErrNotConnected
	}
	var peer *fakeSock
	var ext io.ReadWriteCloser
	var extDdl deadlineConn
	if err == nil {
		peer, ext, extDdl = s.peer, s.ext, s.extDdl
	}
	gn.mu.Unlock()
	if err != nil {
		return -1, err
	}
	if isClosed(s.closed) {
		return -1, ErrSockClosed
	}

	switch {
	case ext != nil:
		if extDdl != nil {
			extDdl.SetWriteDeadline(deadline)
		}
		n, err := ext.Write(buf)
		if n < 0 {
			n = 0
		}
		return n, err

	case peer == nil:
		// Connected datagram socket with no local owner at the far end.
		return len(buf), nil
	}

	for {
		queued, dead := peer.rx.tryPut(buf)
		if dead {
			return -1, ErrConnReset
		}
		if queued {
			return len(buf), nil
		}
		if err := peer.rx.waitDrain(s.closed, deadline); err != nil {
			return -1, err
		}
	}
}

// Recv reads from the connected peer, blocking until data arrives, the peer
// hangs up, or the deadline expires. A stream ignores write boundaries; a
// datagram returns exactly one message, truncated to len(buf) with the rest
// dropped, as a real recv does.
func (gn *GoNetFake) Recv(sockfd int, buf []byte, flags int, deadline time.Time) (int, error) {
	gn.mu.Lock()
	s, err := gn.sockLocked(sockfd)
	if err == nil {
		switch {
		case s.listening:
			err = ErrNotConnected
		case s.ext == nil && s.rx == nil:
			err = ErrNotConnected
		}
	}
	var ext io.ReadWriteCloser
	var extDdl deadlineConn
	if err == nil {
		ext, extDdl = s.ext, s.extDdl
	}
	gn.mu.Unlock()
	if err != nil {
		return -1, err
	}
	if isClosed(s.closed) {
		return -1, ErrSockClosed
	}
	if ext != nil {
		if extDdl != nil {
			extDdl.SetReadDeadline(deadline)
		}
		n, err := ext.Read(buf)
		if n < 0 {
			n = 0
		}
		return n, err
	}
	if len(buf) == 0 {
		return 0, nil
	}

	for {
		n, eof := s.rx.pop(buf)
		if n > 0 {
			return n, nil
		}
		if eof {
			return 0, io.EOF
		}
		if err := s.rx.waitData(s.closed, deadline); err != nil {
			return -1, err
		}
	}
}

// Close releases the socket, waking anything blocked on it. It is idempotent:
// TinyGo's net closes on overlapping error paths.
func (gn *GoNetFake) Close(sockfd int) error {
	gn.mu.Lock()
	s, err := gn.sockLocked(sockfd)
	if err != nil {
		gn.mu.Unlock()
		return err
	}
	delete(gn.socks, sockfd)
	if s.bound {
		if gn.bound[s.laddr] == s {
			delete(gn.bound, s.laddr)
		}
		s.bound = false
	}
	peer, ext, backlog := s.peer, s.ext, s.backlog
	stype := s.stype
	s.peer, s.ext, s.extDdl = nil, nil, nil
	var pending []*fakeSock
	var pendingPeers []*fakeSock
	for backlog != nil {
		// Connections the network accepted but the program never did.
		select {
		case p := <-backlog:
			pending = append(pending, p)
			pendingPeers = append(pendingPeers, p.peer)
			p.peer = nil
			delete(gn.socks, p.fd)
			continue
		default:
		}
		break
	}
	gn.mu.Unlock()

	s.closeOnce.Do(func() { close(s.closed) })
	s.rx.setDead()
	// A stream peer sees end of file once it drains what we sent. A datagram
	// peer sees nothing: it may have other correspondents.
	if peer != nil && stype == _SOCK_STREAM {
		peer.rx.setEOF()
	}
	if ext != nil {
		ext.Close()
	}
	for i, p := range pending {
		p.closeOnce.Do(func() { close(p.closed) })
		p.rx.setDead()
		if peer := pendingPeers[i]; peer != nil {
			peer.rx.setEOF()
		}
	}
	return nil
}

// SetSockOpt accepts every option and applies none, as the standard library's
// own net/sockopt_fake.go does: no stack underneath for one to reach.
func (gn *GoNetFake) SetSockOpt(sockfd, level, opt int, value any) error {
	gn.mu.Lock()
	_, err := gn.sockLocked(sockfd)
	gn.mu.Unlock()
	return err
}

func isClosed(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

// sockQueue holds what a socket was sent: a buffer behind a mutex with two
// condition channels, since there is no runtime poller to park a socket on.
type sockQueue struct {
	stream bool
	limit  int

	mu     sync.Mutex
	msgs   [][]byte
	nbytes int
	eof    bool // writer hung up; reader drains, then sees io.EOF
	dead   bool // reader gone; writers are reset

	data  chan struct{} // readable, or readable-until-EOF
	drain chan struct{} // room freed
}

func newSockQueue(stream bool, limit int) *sockQueue {
	return &sockQueue{
		stream: stream,
		limit:  limit,
		data:   make(chan struct{}, 1),
		drain:  make(chan struct{}, 1),
	}
}

// signal posts to c without blocking. Waiters re-check state on wake, so a post
// landing on a full channel is a wakeup already pending, not one lost.
func signal(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

// tryPut appends b if there is room, reporting whether it was queued and
// whether the queue is finished with writes altogether.
func (q *sockQueue) tryPut(b []byte) (queued, dead bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.dead || q.eof {
		return false, true
	}
	// The limit is a soft one: an empty queue always accepts, so a message
	// larger than the whole buffer moves instead of deadlocking.
	if q.nbytes >= q.limit && q.nbytes > 0 {
		return false, false
	}
	msg := make([]byte, len(b))
	copy(msg, b)
	q.msgs = append(q.msgs, msg)
	q.nbytes += len(msg)
	signal(q.data)
	return true, false
}

// pop moves buffered data into buf, reporting end of file once a hung-up
// writer's data has all been read.
func (q *sockQueue) pop(buf []byte) (n int, eof bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.msgs) > 0 && n < len(buf) {
		msg := q.msgs[0]
		c := copy(buf[n:], msg)
		n += c
		if c == len(msg) || !q.stream {
			// A datagram is consumed whole; its tail is dropped when the
			// caller's buffer was too small.
			q.nbytes -= len(msg)
			q.msgs[0] = nil
			q.msgs = q.msgs[1:]
		} else {
			q.msgs[0] = msg[c:]
			q.nbytes -= c
		}
		if !q.stream {
			break
		}
	}
	if n > 0 {
		signal(q.drain)
		if len(q.msgs) > 0 {
			signal(q.data)
		}
		return n, false
	}
	return 0, q.eof
}

func (q *sockQueue) setEOF() {
	q.mu.Lock()
	q.eof = true
	q.mu.Unlock()
	signal(q.data)
	signal(q.drain)
}

func (q *sockQueue) setDead() {
	q.mu.Lock()
	q.dead = true
	q.mu.Unlock()
	signal(q.data)
	signal(q.drain)
}

func (q *sockQueue) waitData(closed <-chan struct{}, deadline time.Time) error {
	return wait(q.data, closed, deadline)
}

func (q *sockQueue) waitDrain(closed <-chan struct{}, deadline time.Time) error {
	return wait(q.drain, closed, deadline)
}

// wait parks until the queue signals, the socket closes, or the deadline
// passes. Zero waits indefinitely; one already past expires without scheduling.
func wait(sig <-chan struct{}, closed <-chan struct{}, deadline time.Time) error {
	var expire <-chan time.Time
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return ErrTimeout
		}
		t := time.NewTimer(d)
		defer t.Stop()
		expire = t.C
	}
	select {
	case <-sig:
		return nil
	case <-closed:
		return ErrSockClosed
	case <-expire:
		return ErrTimeout
	}
}
