package gonetfake

import (
	"errors"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func addrPort(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return ap
}

// listenStream returns a listening socket and the address to dial it on.
func listenStream(t *testing.T, gn *GoNetFake) (fd int, addr netip.AddrPort) {
	t.Helper()
	fd, err := gn.Socket(_AF_INET, _SOCK_STREAM, _IPPROTO_TCP)
	if err != nil {
		t.Fatalf("Socket: %v", err)
	}
	if err = gn.Bind(fd, netip.AddrPort{}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err = gn.Listen(fd, 4); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	gn.mu.Lock()
	addr = gn.socks[fd].laddr
	gn.mu.Unlock()
	return fd, addr
}

func dialStream(t *testing.T, gn *GoNetFake, addr netip.AddrPort) int {
	t.Helper()
	fd, err := gn.Socket(_AF_INET, _SOCK_STREAM, _IPPROTO_TCP)
	if err != nil {
		t.Fatalf("Socket: %v", err)
	}
	if err = gn.Connect(fd, "", addr); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	return fd
}

func sendAll(t *testing.T, gn *GoNetFake, fd int, b []byte) {
	t.Helper()
	n, err := gn.Send(fd, b, 0, time.Time{})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if n != len(b) {
		t.Fatalf("Send wrote %d, want %d", n, len(b))
	}
}

func recvString(t *testing.T, gn *GoNetFake, fd int, n int) string {
	t.Helper()
	buf := make([]byte, n)
	got, err := gn.Recv(fd, buf, 0, time.Now().Add(2*time.Second))
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	return string(buf[:got])
}

func TestStreamEcho(t *testing.T) {
	gn := &GoNetFake{}
	lfd, addr := listenStream(t, gn)
	cfd := dialStream(t, gn, addr)

	sfd, raddr, err := gn.Accept(lfd)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if !raddr.IsValid() || raddr.Port() == 0 {
		t.Errorf("Accept peer addr = %v, want a bound address", raddr)
	}

	sendAll(t, gn, cfd, []byte("ping"))
	if got := recvString(t, gn, sfd, 16); got != "ping" {
		t.Errorf("server read %q, want %q", got, "ping")
	}
	sendAll(t, gn, sfd, []byte("pong"))
	if got := recvString(t, gn, cfd, 16); got != "pong" {
		t.Errorf("client read %q, want %q", got, "pong")
	}
}

// TestStreamIgnoresWriteBoundaries checks a stream socket coalesces writes, the
// property that distinguishes it from a datagram socket.
func TestStreamIgnoresWriteBoundaries(t *testing.T) {
	gn := &GoNetFake{}
	lfd, addr := listenStream(t, gn)
	cfd := dialStream(t, gn, addr)
	sfd, _, err := gn.Accept(lfd)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

	sendAll(t, gn, cfd, []byte("abc"))
	sendAll(t, gn, cfd, []byte("def"))
	if got := recvString(t, gn, sfd, 16); got != "abcdef" {
		t.Errorf("read %q, want %q", got, "abcdef")
	}
}

// TestStreamShortReadKeepsRemainder checks a stream read that does not consume
// a whole buffered write leaves the rest for the next read.
func TestStreamShortReadKeepsRemainder(t *testing.T) {
	gn := &GoNetFake{}
	lfd, addr := listenStream(t, gn)
	cfd := dialStream(t, gn, addr)
	sfd, _, err := gn.Accept(lfd)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

	sendAll(t, gn, cfd, []byte("abcdef"))
	if got := recvString(t, gn, sfd, 2); got != "ab" {
		t.Errorf("first read %q, want %q", got, "ab")
	}
	if got := recvString(t, gn, sfd, 16); got != "cdef" {
		t.Errorf("second read %q, want %q", got, "cdef")
	}
}

func TestStreamCloseGivesEOF(t *testing.T) {
	gn := &GoNetFake{}
	lfd, addr := listenStream(t, gn)
	cfd := dialStream(t, gn, addr)
	sfd, _, err := gn.Accept(lfd)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

	sendAll(t, gn, cfd, []byte("tail"))
	if err := gn.Close(cfd); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Buffered data must survive the close, and only then does EOF arrive.
	if got := recvString(t, gn, sfd, 16); got != "tail" {
		t.Errorf("read %q, want %q", got, "tail")
	}
	buf := make([]byte, 4)
	n, err := gn.Recv(sfd, buf, 0, time.Now().Add(time.Second))
	if !errors.Is(err, io.EOF) {
		t.Errorf("Recv after peer close = (%d, %v), want io.EOF", n, err)
	}
}

func TestStreamConnectRefused(t *testing.T) {
	gn := &GoNetFake{}
	fd, err := gn.Socket(_AF_INET, _SOCK_STREAM, _IPPROTO_TCP)
	if err != nil {
		t.Fatalf("Socket: %v", err)
	}
	err = gn.Connect(fd, "", addrPort(t, "127.0.0.1:9"))
	if !errors.Is(err, ErrConnRefused) {
		t.Errorf("Connect to unbound port = %v, want ErrConnRefused", err)
	}
}

// TestConnectToNonListenerRefused checks a bound but passive socket does not
// accept connections, as a TCP socket that never called listen does not.
func TestConnectToNonListenerRefused(t *testing.T) {
	gn := &GoNetFake{}
	sfd, err := gn.Socket(_AF_INET, _SOCK_STREAM, _IPPROTO_TCP)
	if err != nil {
		t.Fatalf("Socket: %v", err)
	}
	if err = gn.Bind(sfd, addrPort(t, "127.0.0.1:7100")); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	cfd, err := gn.Socket(_AF_INET, _SOCK_STREAM, _IPPROTO_TCP)
	if err != nil {
		t.Fatalf("Socket: %v", err)
	}
	if err = gn.Connect(cfd, "", addrPort(t, "127.0.0.1:7100")); !errors.Is(err, ErrConnRefused) {
		t.Errorf("Connect to non-listener = %v, want ErrConnRefused", err)
	}
}

// TestAcceptUnblocksOnClose is the one case that needs a second goroutine:
// Accept parks with no deadline, so only a close can end it.
func TestAcceptUnblocksOnClose(t *testing.T) {
	gn := &GoNetFake{}
	lfd, _ := listenStream(t, gn)

	accepted := make(chan error, 1)
	go func() {
		_, _, err := gn.Accept(lfd)
		accepted <- err
	}()

	if err := gn.Close(lfd); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Either error says the listener went away; which one depends on whether
	// Accept had reached its park before Close removed the descriptor.
	var err error
	select {
	case err = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for Accept to return after Close")
	}
	if !errors.Is(err, ErrSockClosed) && !errors.Is(err, ErrBadFD) {
		t.Errorf("Accept after close = %v, want ErrSockClosed or ErrBadFD", err)
	}
}

func bindDatagram(t *testing.T, gn *GoNetFake, port uint16) (fd int, addr netip.AddrPort) {
	t.Helper()
	fd, err := gn.Socket(_AF_INET, _SOCK_DGRAM, _IPPROTO_UDP)
	if err != nil {
		t.Fatalf("Socket: %v", err)
	}
	if err = gn.Bind(fd, netip.AddrPortFrom(netip.Addr{}, port)); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	gn.mu.Lock()
	addr = gn.socks[fd].laddr
	gn.mu.Unlock()
	return fd, addr
}

func TestDatagramRoundTrip(t *testing.T) {
	gn := &GoNetFake{}
	afd, aaddr := bindDatagram(t, gn, 0)
	bfd, baddr := bindDatagram(t, gn, 0)

	if err := gn.Connect(afd, "", baddr); err != nil {
		t.Fatalf("Connect a->b: %v", err)
	}
	if err := gn.Connect(bfd, "", aaddr); err != nil {
		t.Fatalf("Connect b->a: %v", err)
	}
	sendAll(t, gn, afd, []byte("one"))
	if got := recvString(t, gn, bfd, 16); got != "one" {
		t.Errorf("b read %q, want %q", got, "one")
	}
	sendAll(t, gn, bfd, []byte("two"))
	if got := recvString(t, gn, afd, 16); got != "two" {
		t.Errorf("a read %q, want %q", got, "two")
	}
}

// TestDatagramPreservesBoundaries checks each Recv yields exactly one message,
// and that a short buffer drops the rest of it rather than keeping it.
func TestDatagramPreservesBoundaries(t *testing.T) {
	gn := &GoNetFake{}
	afd, _ := bindDatagram(t, gn, 0)
	bfd, baddr := bindDatagram(t, gn, 0)
	if err := gn.Connect(afd, "", baddr); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	sendAll(t, gn, afd, []byte("first"))
	sendAll(t, gn, afd, []byte("second"))
	if got := recvString(t, gn, bfd, 32); got != "first" {
		t.Errorf("read %q, want %q", got, "first")
	}
	if got := recvString(t, gn, bfd, 3); got != "sec" {
		t.Errorf("truncated read %q, want %q", got, "sec")
	}
	// The truncated tail is gone, so the next read must block, not return "ond".
	buf := make([]byte, 32)
	if _, err := gn.Recv(bfd, buf, 0, time.Now().Add(50*time.Millisecond)); !errors.Is(err, ErrTimeout) {
		t.Errorf("Recv after truncation = %v, want ErrTimeout", err)
	}
}

// TestDatagramConnectToNowhereSucceeds checks UDP keeps its asymmetry: with no
// listener to refuse, the connect stands and sends are discarded.
func TestDatagramConnectToNowhereSucceeds(t *testing.T) {
	gn := &GoNetFake{}
	fd, err := gn.Socket(_AF_INET, _SOCK_DGRAM, _IPPROTO_UDP)
	if err != nil {
		t.Fatalf("Socket: %v", err)
	}
	if err = gn.Connect(fd, "", addrPort(t, "203.0.113.1:53")); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	sendAll(t, gn, fd, []byte("into the void"))
}

// TestBindEphemeralPortsDiffer covers what net.freePort exercises: binding port
// zero must yield a usable, distinct port each time.
func TestBindEphemeralPortsDiffer(t *testing.T) {
	gn := &GoNetFake{}
	_, first := bindDatagram(t, gn, 0)
	_, second := bindDatagram(t, gn, 0)

	for _, ap := range []netip.AddrPort{first, second} {
		if p := ap.Port(); p < ephemeralFirst || p > ephemeralLast {
			t.Errorf("port %d outside ephemeral range %d-%d", p, ephemeralFirst, ephemeralLast)
		}
	}
	if first.Port() == second.Port() {
		t.Errorf("both binds got port %d, want distinct", first.Port())
	}
}

func TestBindDuplicateInUse(t *testing.T) {
	gn := &GoNetFake{}
	bindDatagram(t, gn, 7200)
	fd, err := gn.Socket(_AF_INET, _SOCK_DGRAM, _IPPROTO_UDP)
	if err != nil {
		t.Fatalf("Socket: %v", err)
	}
	err = gn.Bind(fd, addrPort(t, "127.0.0.1:7200"))
	if !errors.Is(err, ErrAddrInUse) {
		t.Errorf("duplicate Bind = %v, want ErrAddrInUse", err)
	}
}

// TestBindReleasedOnClose checks a closed socket gives its port back, so a
// restarting listener is not locked out of its own address.
func TestBindReleasedOnClose(t *testing.T) {
	gn := &GoNetFake{}
	fd, _ := bindDatagram(t, gn, 7300)
	if err := gn.Close(fd); err != nil {
		t.Fatalf("Close: %v", err)
	}
	again, err := gn.Socket(_AF_INET, _SOCK_DGRAM, _IPPROTO_UDP)
	if err != nil {
		t.Fatalf("Socket: %v", err)
	}
	if err = gn.Bind(again, addrPort(t, "127.0.0.1:7300")); err != nil {
		t.Errorf("rebind after close: %v", err)
	}
}

func TestRecvDeadlineExpires(t *testing.T) {
	gn := &GoNetFake{}
	afd, _ := bindDatagram(t, gn, 0)
	_, baddr := bindDatagram(t, gn, 0)
	if err := gn.Connect(afd, "", baddr); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	buf := make([]byte, 8)
	start := time.Now()
	_, err := gn.Recv(afd, buf, 0, time.Now().Add(40*time.Millisecond))
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("Recv = %v, want ErrTimeout", err)
	}
	if elapsed := time.Since(start); elapsed < 30*time.Millisecond {
		t.Errorf("Recv returned after %v, want it to wait out the deadline", elapsed)
	}
	var ne interface{ Timeout() bool }
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Errorf("error %v does not report Timeout() true", err)
	}
}

// TestRecvPastDeadlineIsImmediate checks a deadline already gone expires
// without a trip through the scheduler.
func TestRecvPastDeadlineIsImmediate(t *testing.T) {
	gn := &GoNetFake{}
	fd, _ := bindDatagram(t, gn, 0)
	_, baddr := bindDatagram(t, gn, 0)
	if err := gn.Connect(fd, "", baddr); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	buf := make([]byte, 8)
	if _, err := gn.Recv(fd, buf, 0, time.Now().Add(-time.Second)); !errors.Is(err, ErrTimeout) {
		t.Errorf("Recv with past deadline = %v, want ErrTimeout", err)
	}
}

// TestRecvDeadlineNotHitWhenReady checks a pending deadline does not fire on
// data that is already waiting.
func TestRecvDeadlineNotHitWhenReady(t *testing.T) {
	gn := &GoNetFake{}
	afd, _ := bindDatagram(t, gn, 0)
	bfd, baddr := bindDatagram(t, gn, 0)
	if err := gn.Connect(afd, "", baddr); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	sendAll(t, gn, afd, []byte("ready"))
	if got := recvString(t, gn, bfd, 16); got != "ready" {
		t.Errorf("read %q, want %q", got, "ready")
	}
}

// TestSendToClosedPeerResets checks a writer learns its reader is gone rather
// than filling a queue nobody drains.
func TestSendToClosedPeerResets(t *testing.T) {
	gn := &GoNetFake{}
	lfd, addr := listenStream(t, gn)
	cfd := dialStream(t, gn, addr)
	sfd, _, err := gn.Accept(lfd)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if err = gn.Close(sfd); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err = gn.Send(cfd, []byte("hello"), 0, time.Time{}); !errors.Is(err, ErrConnReset) {
		t.Errorf("Send to closed peer = %v, want ErrConnReset", err)
	}
}

// pipeConn is a Dial-supplied far end that echoes whatever it is written.
type pipeConn struct {
	mu     sync.Mutex
	buf    []byte
	closed bool
	ready  chan struct{}
}

func newPipeConn() *pipeConn { return &pipeConn{ready: make(chan struct{}, 1)} }

func (p *pipeConn) Write(b []byte) (int, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	p.buf = append(p.buf, b...)
	p.mu.Unlock()
	select {
	case p.ready <- struct{}{}:
	default:
	}
	return len(b), nil
}

func (p *pipeConn) Read(b []byte) (int, error) {
	for {
		p.mu.Lock()
		if len(p.buf) > 0 {
			n := copy(b, p.buf)
			p.buf = p.buf[n:]
			p.mu.Unlock()
			return n, nil
		}
		if p.closed {
			p.mu.Unlock()
			return 0, io.EOF
		}
		p.mu.Unlock()
		<-p.ready
	}
}

func (p *pipeConn) Close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	select {
	case p.ready <- struct{}{}:
	default:
	}
	return nil
}

func (p *pipeConn) isClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

func TestDialHookCarriesTraffic(t *testing.T) {
	conn := newPipeConn()
	var gotType int
	var gotAddr netip.AddrPort
	gn := &GoNetFake{
		Dial: func(stype int, host string, raddr netip.AddrPort) (io.ReadWriteCloser, error) {
			gotType, gotAddr = stype, raddr
			return conn, nil
		},
	}

	fd, err := gn.Socket(_AF_INET, _SOCK_STREAM, _IPPROTO_TCP)
	if err != nil {
		t.Fatalf("Socket: %v", err)
	}
	want := addrPort(t, "198.51.100.7:443")
	if err = gn.Connect(fd, "", want); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if gotType != _SOCK_STREAM || gotAddr != want {
		t.Errorf("Dial got (%d, %v), want (%d, %v)", gotType, gotAddr, _SOCK_STREAM, want)
	}

	sendAll(t, gn, fd, []byte("through"))
	if got := recvString(t, gn, fd, 16); got != "through" {
		t.Errorf("read %q, want %q", got, "through")
	}
	if err = gn.Close(fd); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !conn.isClosed() {
		t.Error("Close did not close the Dial-supplied conn")
	}
}

// TestDialHookNotUsedForLocal checks a local socket wins over the hook, so
// loopback traffic never leaves the program.
func TestDialHookNotUsedForLocal(t *testing.T) {
	called := false
	gn := &GoNetFake{
		Dial: func(int, string, netip.AddrPort) (io.ReadWriteCloser, error) {
			called = true
			return newPipeConn(), nil
		},
	}
	lfd, addr := listenStream(t, gn)
	cfd := dialStream(t, gn, addr)
	if _, _, err := gn.Accept(lfd); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if called {
		t.Error("Dial hook consulted for an address a local socket owns")
	}
	_ = cfd
}

func TestDialHookError(t *testing.T) {
	boom := errors.New("boom")
	gn := &GoNetFake{
		Dial: func(int, string, netip.AddrPort) (io.ReadWriteCloser, error) {
			return nil, boom
		},
	}
	fd, err := gn.Socket(_AF_INET, _SOCK_STREAM, _IPPROTO_TCP)
	if err != nil {
		t.Fatalf("Socket: %v", err)
	}
	if err = gn.Connect(fd, "", addrPort(t, "198.51.100.7:443")); !errors.Is(err, boom) {
		t.Errorf("Connect = %v, want %v", err, boom)
	}
}

func TestGetHostByName(t *testing.T) {
	gn := &GoNetFake{Hosts: map[string]netip.Addr{
		"mgmt.internal": netip.MustParseAddr("10.0.0.5"),
	}}

	if got, err := gn.GetHostByName("192.0.2.10"); err != nil || got.String() != "192.0.2.10" {
		t.Errorf("literal = (%v, %v), want 192.0.2.10", got, err)
	}
	if got, err := gn.GetHostByName("mgmt.internal"); err != nil || got.String() != "10.0.0.5" {
		t.Errorf("table hit = (%v, %v), want 10.0.0.5", got, err)
	}
	if _, err := gn.GetHostByName("absent.example"); err == nil {
		t.Error("unregistered name resolved, want an error")
	}
}

func TestSocketRejectsUnsupported(t *testing.T) {
	gn := &GoNetFake{}
	for _, tc := range []struct{ domain, stype, proto int }{
		{0xa, _SOCK_STREAM, _IPPROTO_TCP}, // AF_INET6
		{_AF_INET, 0x3, 0},                // SOCK_RAW
		{_AF_INET, _SOCK_STREAM, _IPPROTO_UDP},
		{_AF_INET, _SOCK_DGRAM, _IPPROTO_TCP},
	} {
		if _, err := gn.Socket(tc.domain, tc.stype, tc.proto); !errors.Is(err, ErrSockType) {
			t.Errorf("Socket(%d,%d,%d) = %v, want ErrSockType", tc.domain, tc.stype, tc.proto, err)
		}
	}
}

func TestBadDescriptor(t *testing.T) {
	gn := &GoNetFake{}
	if err := gn.Bind(99, netip.AddrPort{}); !errors.Is(err, ErrBadFD) {
		t.Errorf("Bind(99) = %v, want ErrBadFD", err)
	}
	if _, err := gn.Recv(99, make([]byte, 1), 0, time.Time{}); !errors.Is(err, ErrBadFD) {
		t.Errorf("Recv(99) = %v, want ErrBadFD", err)
	}
	if err := gn.Close(99); !errors.Is(err, ErrBadFD) {
		t.Errorf("Close(99) = %v, want ErrBadFD", err)
	}
}

// TestCloseIsIdempotent matters because TinyGo's net closes on overlapping
// error paths; the second close reports a bad descriptor, it does not panic.
func TestCloseIsIdempotent(t *testing.T) {
	gn := &GoNetFake{}
	fd, _ := bindDatagram(t, gn, 0)
	if err := gn.Close(fd); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := gn.Close(fd); !errors.Is(err, ErrBadFD) {
		t.Errorf("second Close = %v, want ErrBadFD", err)
	}
}

func TestSetSockOptAccepted(t *testing.T) {
	gn := &GoNetFake{}
	fd, _ := listenStream(t, gn)
	if err := gn.SetSockOpt(fd, _SOL_SOCKET, _SO_KEEPALIVE, true); err != nil {
		t.Errorf("SetSockOpt: %v", err)
	}
	if err := gn.SetSockOpt(99, _SOL_SOCKET, _SO_LINGER, 0); !errors.Is(err, ErrBadFD) {
		t.Errorf("SetSockOpt on bad fd = %v, want ErrBadFD", err)
	}
}

func TestAddrDefaultsToLoopback(t *testing.T) {
	gn := &GoNetFake{}
	got, err := gn.Addr()
	if err != nil || got.String() != "127.0.0.1" {
		t.Errorf("Addr = (%v, %v), want 127.0.0.1", got, err)
	}
	gn2 := &GoNetFake{HostAddr: netip.MustParseAddr("10.1.2.3")}
	if got, _ = gn2.Addr(); got.String() != "10.1.2.3" {
		t.Errorf("Addr = %v, want 10.1.2.3", got)
	}
}

// TestSendBlocksWhenQueueFull checks the soft limit applies backpressure rather
// than growing without bound, and that the deadline still governs.
func TestSendBlocksWhenQueueFull(t *testing.T) {
	gn := &GoNetFake{}
	lfd, addr := listenStream(t, gn)
	cfd := dialStream(t, gn, addr)
	sfd, _, err := gn.Accept(lfd)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

	chunk := make([]byte, defaultQueueBytes)
	sendAll(t, gn, cfd, chunk)
	if _, err = gn.Send(cfd, chunk, 0, time.Now().Add(40*time.Millisecond)); !errors.Is(err, ErrTimeout) {
		t.Fatalf("Send into full queue = %v, want ErrTimeout", err)
	}
	// Draining the reader must let the blocked write through.
	if n := len(recvString(t, gn, sfd, defaultQueueBytes)); n != defaultQueueBytes {
		t.Fatalf("drained %d bytes, want %d", n, defaultQueueBytes)
	}
	sendAll(t, gn, cfd, chunk)
}
