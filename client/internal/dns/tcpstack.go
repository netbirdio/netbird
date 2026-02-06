package dns

import (
	"fmt"
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
)

// tcpDNSServer is an on-demand TCP DNS server backed by a minimal gvisor stack.
// It is started lazily when a truncated DNS response is detected and shuts down
// after a period of inactivity to conserve resources.
type tcpDNSServer struct {
	mu      sync.Mutex
	s       *stack.Stack
	ep      *dnsEndpoint
	mux     *dns.ServeMux
	tunDev  tun.Device
	ip      netip.Addr
	port    uint16
	mtu     uint16
	running bool
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

// EnsureRunning starts the TCP stack if not already running and resets the idle timer.
func (t *tcpDNSServer) EnsureRunning() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.running {
		t.resetTimerLocked()
		return
	}

	if err := t.startLocked(); err != nil {
		log.Errorf("start TCP DNS stack: %v", err)
		return
	}

	t.running = true
	t.resetTimerLocked()
	log.Debugf("TCP DNS stack started on %s:%d", t.ip, t.port)
}

// InjectPacket delivers a raw IP packet into the gvisor stack for TCP processing.
func (t *tcpDNSServer) InjectPacket(payload []byte) {
	t.mu.Lock()
	ep := t.ep
	t.mu.Unlock()

	if ep == nil {
		return
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(payload),
	})
	defer pkt.DecRef()

	if ep.dispatcher != nil {
		ep.dispatcher.DeliverNetworkPacket(ipv4.ProtocolNumber, pkt)
	}
}

// Stop tears down the gvisor stack and releases resources.
func (t *tcpDNSServer) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.stopLocked()
}

func (t *tcpDNSServer) startLocked() error {
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
		return fmt.Errorf("add protocol address: %s", err)
	}

	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return fmt.Errorf("set promiscuous mode: %s", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return fmt.Errorf("set spoofing: %s", err)
	}

	defaultSubnet, err := tcpip.NewSubnet(
		tcpip.AddrFrom4([4]byte{0, 0, 0, 0}),
		tcpip.MaskFromBytes([]byte{0, 0, 0, 0}),
	)
	if err != nil {
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
	t.timer = time.AfterFunc(dnsTCPIdleTimeout, func() {
		t.mu.Lock()
		defer t.mu.Unlock()

		t.stopLocked()
	})
}

func (t *tcpDNSServer) handleTCPDNS(r *tcp.ForwarderRequest) {
	id := r.ID()

	wq := waiter.Queue{}
	ep, epErr := r.CreateEndpoint(&wq)
	if epErr != nil {
		log.Debugf("TCP DNS: create endpoint: %v", epErr)
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
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			break
		}

		msg, err := readTCPDNSMessage(conn)
		if err != nil {
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
func (e *dnsEndpoint) Wait()                                        {}
func (e *dnsEndpoint) ARPHardwareType() header.ARPHardwareType      { return header.ARPHardwareNone }
func (e *dnsEndpoint) AddHeader(*stack.PacketBuffer)                {}
func (e *dnsEndpoint) ParseHeader(*stack.PacketBuffer) bool         { return true }
func (e *dnsEndpoint) Close()                                       {}
func (e *dnsEndpoint) SetLinkAddress(tcpip.LinkAddress)             {}
func (e *dnsEndpoint) SetMTU(mtu uint32)                            { e.mtu.Store(mtu) }
func (e *dnsEndpoint) SetOnCloseAction(func())                      {}

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

		if _, err := e.tunDev.Write([][]byte{buf}, tunPacketOffset); err != nil {
			log.Tracef("TCP DNS endpoint: write packet: %v", err)
			continue
		}
		written++
	}
	return written, nil
}

// readTCPDNSMessage reads a single DNS message from a TCP connection (length-prefixed).
func readTCPDNSMessage(conn *gonet.TCPConn) (*dns.Msg, error) {
	// DNS over TCP uses a 2-byte length prefix
	lenBuf := make([]byte, 2)
	if _, err := readFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}

	msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
	if msgLen == 0 || msgLen > 65535 {
		return nil, fmt.Errorf("invalid message length: %d", msgLen)
	}

	msgBuf := make([]byte, msgLen)
	if _, err := readFull(conn, msgBuf); err != nil {
		return nil, fmt.Errorf("read message: %w", err)
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(msgBuf); err != nil {
		return nil, fmt.Errorf("unpack: %w", err)
	}
	return msg, nil
}

func readFull(conn *gonet.TCPConn, buf []byte) (int, error) {
	var total int
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
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
	return w.conn.Write(data)
}

func (w *tcpResponseWriter) Close() error {
	return w.conn.Close()
}

func (w *tcpResponseWriter) TsigStatus() error   { return nil }
func (w *tcpResponseWriter) TsigTimersOnly(bool) {}
func (w *tcpResponseWriter) Hijack()             {}
