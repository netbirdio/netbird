//go:build linux && !android

// Inspired by
// Jason Donenfeld (https://git.zx2c4.com/wireguard-tools/tree/contrib/nat-hole-punching/nat-punch-client.c#n96)
// and @stv0g in https://github.com/stv0g/cunicu/tree/ebpf-poc/ebpf_poc

package sharedsock

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
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	nbnet "github.com/netbirdio/netbird/client/net"
)

// ErrSharedSockStopped indicates that shared socket has been stopped
var ErrSharedSockStopped = fmt.Errorf("shared socked stopped")

// SharedSocket is a net.PacketConn that initiates two raw sockets (ipv4 and ipv6) and listens to UDP packets filtered
// by BPF instructions (e.g., IncomingSTUNFilter that checks and sends only STUN packets to the listeners (ReadFrom)).
// It is meant to be used when sharing a port with some other process.
type SharedSocket struct {
	ctx         context.Context
	conn4       *socket.Conn
	conn6       *socket.Conn
	port        int
	mtu         uint16
	routerMux   sync.RWMutex
	router      routing.Router
	packetDemux chan rcvdPacket
	cancel      context.CancelFunc
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

// Maximum overhead for IP + UDP headers on raw socket
// IPv4: max 60 bytes (20 base + 40 options) + UDP 8 bytes = 68 bytes
// IPv6: 40 bytes + UDP 8 bytes = 48 bytes
// We use the maximum (68) for both IPv4 and IPv6
const maxIPUDPOverhead = 68

// Listen creates an IPv4 and IPv6 raw sockets, starts a reader and routing table routines
func Listen(port int, filter BPFFilter, mtu uint16) (_ net.PacketConn, err error) {
	ctx, cancel := context.WithCancel(context.Background())
	rawSock := &SharedSocket{
		ctx:         ctx,
		cancel:      cancel,
		mtu:         mtu,
		port:        port,
		packetDemux: make(chan rcvdPacket),
	}

	defer func() {
		if err != nil {
			if closeErr := rawSock.Close(); closeErr != nil {
				log.Errorf("Failed to close raw socket: %v", closeErr)
			}
		}
	}()

	rawSock.router, err = netroute.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create raw socket router: %w", err)
	}

	rawSock.conn4, err = socket.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_UDP, "raw_udp4", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create ipv4 raw socket: %w", err)
	}

	if err = nbnet.SetSocketMark(rawSock.conn4); err != nil {
		return nil, fmt.Errorf("set SO_MARK on ipv4 socket: %w", err)
	}

	var sockErr error
	rawSock.conn6, sockErr = socket.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_UDP, "raw_udp6", nil)
	if sockErr != nil {
		log.Errorf("Failed to create ipv6 raw socket: %v", err)
	} else {
		if err = nbnet.SetSocketMark(rawSock.conn6); err != nil {
			return nil, fmt.Errorf("set SO_MARK on ipv6 socket: %w", err)
		}
	}

	ipv4Instructions, ipv6Instructions, err := filter.GetInstructions(uint32(rawSock.port))
	if err != nil {
		return nil, fmt.Errorf("getBPFInstructions failed with: %w", err)
	}

	err = rawSock.conn4.SetBPF(ipv4Instructions)
	if err != nil {
		return nil, fmt.Errorf("socket4.SetBPF failed with: %w", err)
	}
	if rawSock.conn6 != nil {
		err = rawSock.conn6.SetBPF(ipv6Instructions)
		if err != nil {
			return nil, fmt.Errorf("socket6.SetBPF failed with: %w", err)
		}
	}

	go rawSock.read(rawSock.conn4.Recvfrom)
	if rawSock.conn6 != nil {
		go rawSock.read(rawSock.conn6.Recvfrom)
	}

	go rawSock.updateRouter()

	return rawSock, nil
}

// updateRouter updates the listener routing table client
// this is needed to avoid outdated information across different client networks
func (s *SharedSocket) updateRouter() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			router, err := netroute.New()
			if err != nil {
				log.Errorf("Failed to create and update packet router for stunListener: %s", err)
				continue
			}
			s.routerMux.Lock()
			s.router = router
			s.routerMux.Unlock()
		}
	}
}

// LocalAddr returns the local address, preferring IPv4 for backward compatibility.
func (s *SharedSocket) LocalAddr() net.Addr {
	if s.conn4 != nil {
		return &net.UDPAddr{
			IP:   net.IPv4zero,
			Port: s.port,
		}
	}
	if s.conn6 != nil {
		return &net.UDPAddr{
			IP:   net.IPv6zero,
			Port: s.port,
		}
	}
	return &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: s.port,
	}
}

// SetDeadline sets both the read and write deadlines associated with the ipv4 and ipv6 Conn sockets
func (s *SharedSocket) SetDeadline(t time.Time) error {
	err := s.conn4.SetDeadline(t)
	if err != nil {
		return fmt.Errorf("s.conn4.SetDeadline error: %w", err)
	}
	if s.conn6 == nil {
		return nil
	}

	err = s.conn6.SetDeadline(t)
	if err != nil {
		return fmt.Errorf("s.conn6.SetDeadline error: %w", err)
	}
	return nil
}

// SetReadDeadline sets the read deadline associated with the ipv4 and ipv6 Conn sockets
func (s *SharedSocket) SetReadDeadline(t time.Time) error {
	err := s.conn4.SetReadDeadline(t)
	if err != nil {
		return fmt.Errorf("s.conn4.SetReadDeadline error: %w", err)
	}
	if s.conn6 == nil {
		return nil
	}

	err = s.conn6.SetReadDeadline(t)
	if err != nil {
		return fmt.Errorf("s.conn6.SetReadDeadline error: %w", err)
	}
	return nil
}

// SetWriteDeadline sets the write deadline associated with the ipv4 and ipv6 Conn sockets
func (s *SharedSocket) SetWriteDeadline(t time.Time) error {
	err := s.conn4.SetWriteDeadline(t)
	if err != nil {
		return fmt.Errorf("s.conn4.SetWriteDeadline error: %w", err)
	}
	if s.conn6 == nil {
		return nil
	}

	err = s.conn6.SetWriteDeadline(t)
	if err != nil {
		return fmt.Errorf("s.conn6.SetWriteDeadline error: %w", err)
	}
	return nil
}

// Close closes the underlying ipv4 and ipv6 conn sockets
func (s *SharedSocket) Close() error {
	s.cancel()
	errGrp := errgroup.Group{}
	if s.conn4 != nil {
		errGrp.Go(s.conn4.Close)
	}

	if s.conn6 != nil {
		errGrp.Go(s.conn6.Close)
	}
	return errGrp.Wait()
}

// read start a read loop for a specific receiver and sends the packet to the packetDemux channel
func (s *SharedSocket) read(receiver receiver) {
	for {
		buf := make([]byte, s.mtu+maxIPUDPOverhead)
		n, addr, err := receiver(s.ctx, buf, 0)
		select {
		case <-s.ctx.Done():
			return
		case s.packetDemux <- rcvdPacket{n, addr, buf[:n], err}:
		}
	}
}

// ReadFrom reads packets received in the packetDemux channel
func (s *SharedSocket) ReadFrom(b []byte) (int, net.Addr, error) {
	var pkt rcvdPacket
	select {
	case <-s.ctx.Done():
		return -1, nil, ErrSharedSockStopped
	case pkt = <-s.packetDemux:
	}

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

	if err := parser.DecodeLayers(pkt.buf, &decodedLayers); err != nil {
		return 0, nil, err
	}

	remoteAddr := &net.UDPAddr{
		IP:   ip,
		Port: int(udp.SrcPort),
	}

	n := copy(b, payload)
	return n, remoteAddr, nil
}

// WriteTo builds a UDP packet and writes it using the specific IP version writer
func (s *SharedSocket) WriteTo(buf []byte, rAddr net.Addr) (n int, err error) {
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
		return 0, fmt.Errorf("got an error while checking route, err: %w", err)
	}

	rSockAddr, conn, nwLayer := s.getWriterObjects(src, rUDPAddr.IP)

	if err := udp.SetNetworkLayerForChecksum(nwLayer); err != nil {
		return -1, fmt.Errorf("failed to set network layer for checksum: %w", err)
	}

	if err := gopacket.SerializeLayers(buffer, writeSerializerOptions, udp, payload); err != nil {
		return -1, fmt.Errorf("failed serialize rcvdPacket: %w", err)
	}

	bufser := buffer.Bytes()

	return 0, conn.Sendto(context.TODO(), bufser, 0, rSockAddr)
}

// getWriterObjects returns the specific IP version objects that are used to build a packet and send it using the raw socket
func (s *SharedSocket) getWriterObjects(src, dest net.IP) (sa unix.Sockaddr, conn *socket.Conn, layer gopacket.NetworkLayer) {
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
