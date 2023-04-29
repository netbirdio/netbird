//go:build linux && !android

// stunlistener is inspired by the implementations of
// Jason Donenfeld (https://git.zx2c4.com/wireguard-tools/tree/contrib/nat-hole-punching/nat-punch-client.c#n96)
// and @stv0g in https://github.com/stv0g/cunicu/tree/ebpf-poc/ebpf_poc it initiates two raw sockets that
// listens to UDP packets filtered by BPF instructions that checks and sends only stun packets to the listeners.

package stunlistener

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/routing"
	"github.com/libp2p/go-netroute"
	"github.com/mdlayher/socket"
	"github.com/pion/stun"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

type STUNMsgHandler func(msg *stun.Message, addr net.Addr) error

// StunListener representation
type StunListener struct {
	ctx         context.Context
	conn4       *socket.Conn
	conn6       *socket.Conn
	port        int
	routerMux   sync.RWMutex
	router      routing.Router
	packetDemux chan rcvdPacket
}

type rcvdPacket struct {
	n    int
	addr unix.Sockaddr
	buf  []byte
	err  error
}

type receiver func(ctx context.Context, p []byte, flags int) (int, unix.Sockaddr, error)

var writeSerializerOptions = gopacket.SerializeOptions{
	ComputeChecksums: true,
	FixLengths:       true,
}

// NewStunListener creates a new stun listener
func NewStunListener(ctx context.Context, port int) *StunListener {
	s := &StunListener{
		ctx:         ctx,
		port:        port,
		packetDemux: make(chan rcvdPacket),
	}
	return s
}

// Listen creates an IPv4 and IPv6 raw sockets, starts a reader and routing table routines
func (s *StunListener) Listen(msgHandler STUNMsgHandler) error {
	var err error

	s.router, err = netroute.New()
	if err != nil {
		return fmt.Errorf("failed to create router: %s", err)
	}

	s.conn4, err = socket.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_UDP, "raw_udp4", nil)
	if err != nil {
		return fmt.Errorf("socket.Socket for ipv4 failed with: %s", err)
	}

	s.conn6, err = socket.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_UDP, "raw_udp6", nil)
	if err != nil {
		log.Errorf("socket.Socket for ipv6 failed with: %s", err)
	}

	ipv4Instructions, ipv6Instructions, err := getBPFInstructions(uint32(s.port))
	if err != nil {
		_ = s.Close()
		return fmt.Errorf("getBPFInstructions failed with: %s", err)
	}

	err = s.conn4.SetBPF(ipv4Instructions)
	if err != nil {
		_ = s.Close()
		return fmt.Errorf("socket4.SetBPF failed with: %s", err)
	}
	if s.conn6 != nil {
		err = s.conn6.SetBPF(ipv6Instructions)
		if err != nil {
			_ = s.Close()
			return fmt.Errorf("socket6.SetBPF failed with: %s", err)
		}
	}

	go s.read(s.conn4.Recvfrom)
	if s.conn6 != nil {
		go s.read(s.conn6.Recvfrom)
	}

	go s.updateRouter()

	go s.listenerToMux(msgHandler)
	return nil
}

// listenerToMux reads a stun message packet and sends to the udp mux handler
func (s *StunListener) listenerToMux(msgHandler STUNMsgHandler) {
	buf := make([]byte, 1500)
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			_, a, err := s.ReadFrom(buf)
			if err != nil {
				log.Errorf("listenerToMux got an error while reading listener packet")
				continue
			}
			msg := &stun.Message{
				Raw: buf,
			}
			err = msg.Decode()
			if err != nil {
				log.Errorf("listenerToMux got an error while parsing stun message: %s", err)
				continue
			}

			err = msgHandler(msg, a)
			if err != nil {
				log.Errorf("listenerToMux got an error while handling stun message: %s", err)
			}
		}
	}
}

// updateRouter updates the listener routing table client
// this is needed to avoid outdated information across different client networks
func (s *StunListener) updateRouter() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			router, err := netroute.New()
			if err != nil {
				log.Errorf("failed to create and update packet router for stunListener: %s", err)
				continue
			}
			s.routerMux.Lock()
			s.router = router
			s.routerMux.Unlock()
		}
	}
}

// LocalAddr returns an IPv4 address using the supplied port
func (s *StunListener) LocalAddr() net.Addr {
	// todo check impact on ipv6 discovery
	return &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: s.port,
	}
}

// SetDeadline sets both the read and write deadlines associated with the ipv4 and ipv6 Conn sockets
func (s *StunListener) SetDeadline(t time.Time) error {
	err := s.conn4.SetDeadline(t)
	if err != nil {
		return fmt.Errorf("s.conn4.SetDeadline error: %s", err)
	}
	if s.conn6 == nil {
		return nil
	}

	err = s.conn6.SetDeadline(t)
	if err != nil {
		return fmt.Errorf("s.conn6.SetDeadline error: %s", err)
	}
	return nil
}

// SetReadDeadline sets the read deadline associated with the ipv4 and ipv6 Conn sockets
func (s *StunListener) SetReadDeadline(t time.Time) error {
	err := s.conn4.SetReadDeadline(t)
	if err != nil {
		return fmt.Errorf("s.conn4.SetReadDeadline error: %s", err)
	}
	if s.conn6 == nil {
		return nil
	}

	err = s.conn6.SetReadDeadline(t)
	if err != nil {
		return fmt.Errorf("s.conn6.SetReadDeadline error: %s", err)
	}
	return nil
}

// SetWriteDeadline sets the write deadline associated with the ipv4 and ipv6 Conn sockets
func (s *StunListener) SetWriteDeadline(t time.Time) error {
	err := s.conn4.SetWriteDeadline(t)
	if err != nil {
		return fmt.Errorf("s.conn4.SetWriteDeadline error: %s", err)
	}
	if s.conn6 == nil {
		return nil
	}

	err = s.conn6.SetWriteDeadline(t)
	if err != nil {
		return fmt.Errorf("s.conn6.SetWriteDeadline error: %s", err)
	}
	return nil
}

// Close closes the underlying ipv4 and ipv6 conn sockets
func (s *StunListener) Close() error {
	errGrp := errgroup.Group{}
	errGrp.Go(s.conn4.Close)
	if s.conn6 != nil {
		errGrp.Go(s.conn6.Close)
	}
	return errGrp.Wait()
}

// read start a read loop for a specific receiver and sends the packet to the packetDemux channel
func (s *StunListener) read(receiver receiver) {
	for {
		buf := make([]byte, 1500)
		n, addr, err := receiver(s.ctx, buf, 0)
		select {
		case <-s.ctx.Done():
			return
		case s.packetDemux <- rcvdPacket{n, addr, buf[:], err}:
		}
	}
}

// ReadFrom reads packets received in the packetDemux channel
func (s *StunListener) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	pkt := <-s.packetDemux

	if pkt.err != nil {
		return -1, nil, pkt.err
	}
	var ip4layer layers.IPv4
	var udp layers.UDP
	var payload gopacket.Payload
	var parser *gopacket.DecodingLayerParser
	var ip net.IP

	if sa, isIPv4 := pkt.addr.(*unix.SockaddrInet4); isIPv4 {
		ip = sa.Addr[:]
		parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4layer, &udp, &payload)
	} else if sa, isIPv6 := pkt.addr.(*unix.SockaddrInet6); isIPv6 {
		ip = sa.Addr[:]
		parser = gopacket.NewDecodingLayerParser(layers.LayerTypeUDP, &udp, &payload)
	} else {
		return -1, nil, fmt.Errorf("received invalid address family")
	}

	decodedLayers := make([]gopacket.LayerType, 0, 3)

	err = parser.DecodeLayers(pkt.buf[:], &decodedLayers)
	if err != nil {
		return 0, nil, err
	}

	remoteAddr := &net.UDPAddr{
		IP:   ip,
		Port: int(udp.SrcPort),
	}

	copy(b, payload)
	return int(udp.Length), remoteAddr, nil
}

// WriteTo builds a UDP packet and writes it using the specific IP version writter
func (s *StunListener) WriteTo(buf []byte, rAddr net.Addr) (n int, err error) {
	rUDPAddr, ok := rAddr.(*net.UDPAddr)
	if !ok {
		return -1, fmt.Errorf("invalid address type")
	}

	buffer := gopacket.NewSerializeBuffer()
	payload := gopacket.Payload(buf)

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(s.port),
		DstPort: layers.UDPPort(rUDPAddr.Port),
	}

	s.routerMux.RLock()
	defer s.routerMux.RUnlock()

	_, _, src, err := s.router.Route(rUDPAddr.IP)
	if err != nil {
		return 0, fmt.Errorf("got an error while checking route, err: %s", err)
	}

	rSockAddr, conn, nwLayer := s.getWritterObjects(src, rUDPAddr.IP)

	if err := udp.SetNetworkLayerForChecksum(nwLayer); err != nil {
		return -1, fmt.Errorf("failed to set network layer for checksum: %w", err)
	}

	if err := gopacket.SerializeLayers(buffer, writeSerializerOptions, udp, payload); err != nil {
		return -1, fmt.Errorf("failed serialize rcvdPacket: %s", err)
	}

	bufser := buffer.Bytes()

	return 0, conn.Sendto(context.TODO(), bufser, 0, rSockAddr)
}

// getWritterObjects returns the specific IP version objects that are used to build a packet and send it using the raw socket
func (s *StunListener) getWritterObjects(src, dest net.IP) (sa unix.Sockaddr, conn *socket.Conn, layer gopacket.NetworkLayer) {
	if dest.To4() == nil {
		sa = &unix.SockaddrInet6{}
		copy(sa.(*unix.SockaddrInet6).Addr[:], dest.To16())
		conn = s.conn6

		layer = &layers.IPv6{
			SrcIP: src,
			DstIP: dest,
		}
	} else {
		sa = &unix.SockaddrInet4{}
		copy(sa.(*unix.SockaddrInet4).Addr[:], dest.To4())
		conn = s.conn4
		layer = &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    src,
			DstIP:    dest,
		}
	}

	return sa, conn, layer
}
