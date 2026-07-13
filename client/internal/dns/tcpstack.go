package dns

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	dnsTCPReceiveWindow = 8192
	dnsTCPMaxInFlight   = 16
	dnsTCPIdleTimeout   = 30 * time.Second
	dnsTCPReadTimeout   = 5 * time.Second
)

// tcpDNSServer is an on-demand TCP DNS server backed by a minimal gvisor stack.
// It is started lazily when a truncated DNS response is detected and shuts down
// after a period of inactivity to conserve resources.
type tcpDNSServer struct {
	mu     sync.Mutex
	s      *stack.Stack
	ep     *dnsEndpoint
	mux    *dns.ServeMux
	tunDev tun.Device
	ip     netip.Addr
	port   uint16
	mtu    uint16

	running bool
	closed  bool
	timerID uint64
	timer   *time.Timer
}

func newTCPDNSServer(mux *dns.ServeMux, tunDev tun.Device, ip netip.Addr, port uint16, mtu uint16) *tcpDNSServer {
	return &tcpDNSServer{
		mux:    mux,
		tunDev: tunDev,
		ip:     ip,
		port:   port,
		mtu:    mtu,
	}
}

// InjectPacket ensures the stack is running and delivers a raw IP packet into
// the gvisor stack for TCP processing. Combining both operations under a single
// lock prevents a race where the idle timer could stop the stack between
// start and delivery.
func (t *tcpDNSServer) InjectPacket(payload []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return
	}

	if !t.running {
		if err := t.startLocked(); err != nil {
			log.Errorf("failed to start TCP DNS stack: %v", err)
			return
		}
		t.running = true
		log.Debugf("TCP DNS stack started on %s:%d (triggered by %s)", t.ip, t.port, srcAddrFromPacket(payload))
	}
	t.resetTimerLocked()

	ep := t.ep
	if ep == nil || ep.dispatcher == nil {
		return
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(payload),
	})
	// DeliverNetworkPacket takes ownership of the packet buffer; do not DecRef.
	ep.dispatcher.DeliverNetworkPacket(ipv4.ProtocolNumber, pkt)
}

// Stop tears down the gvisor stack and releases resources permanently.
// After Stop, InjectPacket becomes a no-op.
func (t *tcpDNSServer) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.stopLocked()
	t.closed = true
}

func (t *tcpDNSServer) startLocked() error {
	// TODO: add ipv6.NewProtocol when IPv6 overlay support lands.
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		HandleLocal:        false,
	})

	nicID := tcpip.NICID(1)
	ep := &dnsEndpoint{
		tunDev: t.tunDev,
	}
	ep.mtu.Store(uint32(t.mtu))

	if err := s.CreateNIC(nicID, ep); err != nil {
		s.Close()
		s.Wait()
		return fmt.Errorf("create NIC: %v", err)
	}

	protoAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(t.ip.AsSlice()),
			PrefixLen: 32,
		},
	}
	if err := s.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
		s.Close()
		s.Wait()
		return fmt.Errorf("add protocol address: %s", err)
	}

	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		s.Close()
		s.Wait()
		return fmt.Errorf("set promiscuous mode: %s", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		s.Close()
		s.Wait()
		return fmt.Errorf("set spoofing: %s", err)
	}

	defaultSubnet, err := tcpip.NewSubnet(
		tcpip.AddrFrom4([4]byte{0, 0, 0, 0}),
		tcpip.MaskFromBytes([]byte{0, 0, 0, 0}),
	)
	if err != nil {
		s.Close()
		s.Wait()
		return fmt.Errorf("create default subnet: %w", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{Destination: defaultSubnet, NIC: nicID},
	})

	tcpFwd := tcp.NewForwarder(s, dnsTCPReceiveWindow, dnsTCPMaxInFlight, func(r *tcp.ForwarderRequest) {
		t.handleTCPDNS(r)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	t.s = s
	t.ep = ep
	return nil
}

func (t *tcpDNSServer) stopLocked() {
	if !t.running {
		return
	}

	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}

	if t.s != nil {
		t.s.Close()
		t.s.Wait()
		t.s = nil
	}
	t.ep = nil
	t.running = false

	log.Debugf("TCP DNS stack stopped")
}

func (t *tcpDNSServer) resetTimerLocked() {
	if t.timer != nil {
		t.timer.Stop()
	}
	t.timerID++
	id := t.timerID
	t.timer = time.AfterFunc(dnsTCPIdleTimeout, func() {
		t.mu.Lock()
		defer t.mu.Unlock()

		// Only stop if this timer is still the active one.
		// A racing InjectPacket may have replaced it.
		if t.timerID != id {
			return
		}
		t.stopLocked()
	})
}

func (t *tcpDNSServer) handleTCPDNS(r *tcp.ForwarderRequest) {
	id := r.ID()

	wq := waiter.Queue{}
	ep, epErr := r.CreateEndpoint(&wq)
	if epErr != nil {
		log.Debugf("TCP DNS: failed to create endpoint: %v", epErr)
		r.Complete(true)
		return
	}
	r.Complete(false)

	conn := gonet.NewTCPConn(&wq, ep)
	defer func() {
		if err := conn.Close(); err != nil {
			log.Tracef("TCP DNS: close conn: %v", err)
		}
	}()

	// Reset idle timer on activity
	t.mu.Lock()
	t.resetTimerLocked()
	t.mu.Unlock()

	localAddr := &net.TCPAddr{
		IP:   id.LocalAddress.AsSlice(),
		Port: int(id.LocalPort),
	}
	remoteAddr := &net.TCPAddr{
		IP:   id.RemoteAddress.AsSlice(),
		Port: int(id.RemotePort),
	}

	for {
		if err := conn.SetReadDeadline(time.Now().Add(dnsTCPReadTimeout)); err != nil {
			log.Debugf("TCP DNS: set deadline for %s: %v", remoteAddr, err)
			break
		}

		msg, err := readTCPDNSMessage(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				log.Debugf("TCP DNS: read from %s: %v", remoteAddr, err)
			}
			break
		}

		writer := &tcpResponseWriter{
			conn:       conn,
			localAddr:  localAddr,
			remoteAddr: remoteAddr,
		}
		t.mux.ServeDNS(writer, msg)
	}
}

// dnsEndpoint implements stack.LinkEndpoint for writing packets back via the tun device.
type dnsEndpoint struct {
	dispatcher stack.NetworkDispatcher
	tunDev     tun.Device
	mtu        atomic.Uint32
}

func (e *dnsEndpoint) Attach(dispatcher stack.NetworkDispatcher)    { e.dispatcher = dispatcher }
func (e *dnsEndpoint) IsAttached() bool                             { return e.dispatcher != nil }
func (e *dnsEndpoint) MTU() uint32                                  { return e.mtu.Load() }
func (e *dnsEndpoint) Capabilities() stack.LinkEndpointCapabilities { return stack.CapabilityNone }
func (e *dnsEndpoint) MaxHeaderLength() uint16                      { return 0 }
func (e *dnsEndpoint) LinkAddress() tcpip.LinkAddress               { return "" }
func (e *dnsEndpoint) Wait()                                        { /* no async work */ }
func (e *dnsEndpoint) ARPHardwareType() header.ARPHardwareType      { return header.ARPHardwareNone }
func (e *dnsEndpoint) AddHeader(*stack.PacketBuffer)                { /* IP-level endpoint, no link header */ }
func (e *dnsEndpoint) ParseHeader(*stack.PacketBuffer) bool         { return true }
func (e *dnsEndpoint) Close()                                       { /* lifecycle managed by tcpDNSServer */ }
func (e *dnsEndpoint) SetLinkAddress(tcpip.LinkAddress)             { /* no link address for tun */ }
func (e *dnsEndpoint) SetMTU(mtu uint32)                            { e.mtu.Store(mtu) }
func (e *dnsEndpoint) SetOnCloseAction(func())                      { /* not needed */ }

const tunPacketOffset = 40

func (e *dnsEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	var written int
	for _, pkt := range pkts.AsSlice() {
		data := stack.PayloadSince(pkt.NetworkHeader())
		if data == nil {
			continue
		}

		raw := data.AsSlice()
		buf := make([]byte, tunPacketOffset, tunPacketOffset+len(raw))
		buf = append(buf, raw...)
		data.Release()

		if _, err := e.tunDev.Write([][]byte{buf}, tunPacketOffset); err != nil {
			log.Tracef("TCP DNS endpoint: failed to write packet: %v", err)
			continue
		}
		written++
	}
	return written, nil
}

// tcpResponseWriter implements dns.ResponseWriter for TCP DNS connections.
type tcpResponseWriter struct {
	conn       *gonet.TCPConn
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (w *tcpResponseWriter) LocalAddr() net.Addr {
	return w.localAddr
}

func (w *tcpResponseWriter) RemoteAddr() net.Addr {
	return w.remoteAddr
}

func (w *tcpResponseWriter) WriteMsg(msg *dns.Msg) error {
	data, err := msg.Pack()
	if err != nil {
		return fmt.Errorf("pack: %w", err)
	}

	// DNS TCP: 2-byte length prefix + message
	buf := make([]byte, 2+len(data))
	buf[0] = byte(len(data) >> 8)
	buf[1] = byte(len(data))
	copy(buf[2:], data)

	if _, err = w.conn.Write(buf); err != nil {
		return err
	}
	return nil
}

func (w *tcpResponseWriter) Write(data []byte) (int, error) {
	buf := make([]byte, 2+len(data))
	buf[0] = byte(len(data) >> 8)
	buf[1] = byte(len(data))
	copy(buf[2:], data)
	if _, err := w.conn.Write(buf); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (w *tcpResponseWriter) Close() error {
	return w.conn.Close()
}

func (w *tcpResponseWriter) TsigStatus() error   { return nil }
func (w *tcpResponseWriter) TsigTimersOnly(bool) { /* TSIG not supported */ }
func (w *tcpResponseWriter) Hijack()             { /* not supported */ }

// readTCPDNSMessage reads a single DNS message from a TCP connection (length-prefixed).
func readTCPDNSMessage(conn *gonet.TCPConn) (*dns.Msg, error) {
	// DNS over TCP uses a 2-byte length prefix
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}

	msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if msgLen == 0 || msgLen > 65535 {
		return nil, fmt.Errorf("invalid message length: %d", msgLen)
	}

	msgBuf := make([]byte, msgLen)
	if _, err := io.ReadFull(conn, msgBuf); err != nil {
		return nil, fmt.Errorf("read message: %w", err)
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(msgBuf); err != nil {
		return nil, fmt.Errorf("unpack: %w", err)
	}
	return msg, nil
}

// srcAddrFromPacket extracts the source IP:port from a raw IP+TCP packet for logging.
// Supports both IPv4 and IPv6.
func srcAddrFromPacket(pkt []byte) netip.AddrPort {
	if len(pkt) == 0 {
		return netip.AddrPort{}
	}

	srcIP, transportOffset := srcIPFromPacket(pkt)
	if !srcIP.IsValid() || len(pkt) < transportOffset+2 {
		return netip.AddrPort{}
	}

	srcPort := uint16(pkt[transportOffset])<<8 | uint16(pkt[transportOffset+1])
	return netip.AddrPortFrom(srcIP.Unmap(), srcPort)
}

func srcIPFromPacket(pkt []byte) (netip.Addr, int) {
	switch header.IPVersion(pkt) {
	case 4:
		return srcIPv4(pkt)
	case 6:
		return srcIPv6(pkt)
	default:
		return netip.Addr{}, 0
	}
}

func srcIPv4(pkt []byte) (netip.Addr, int) {
	if len(pkt) < header.IPv4MinimumSize {
		return netip.Addr{}, 0
	}
	hdr := header.IPv4(pkt)
	src := hdr.SourceAddress()
	ip, ok := netip.AddrFromSlice(src.AsSlice())
	if !ok {
		return netip.Addr{}, 0
	}
	return ip, int(hdr.HeaderLength())
}

func srcIPv6(pkt []byte) (netip.Addr, int) {
	if len(pkt) < header.IPv6MinimumSize {
		return netip.Addr{}, 0
	}
	hdr := header.IPv6(pkt)
	src := hdr.SourceAddress()
	ip, ok := netip.AddrFromSlice(src.AsSlice())
	if !ok {
		return netip.Addr{}, 0
	}
	return ip, header.IPv6MinimumSize
}
