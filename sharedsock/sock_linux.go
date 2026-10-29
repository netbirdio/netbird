//go:build linux && !android

// Inspired by
// Jason Donenfeld (https://git.zx2c4.com/wireguard-tools/tree/contrib/nat-hole-punching/nat-punch-client.c#n96)
// and @stv0g in https://github.com/stv0g/cunicu/tree/ebpf-poc/ebpf_poc

package sharedsock

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mdlayher/socket"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	nbnet "github.com/netbirdio/netbird/client/net"
)

// ErrSharedSockStopped indicates that shared socket has been stopped
var ErrSharedSockStopped = fmt.Errorf("shared socket stopped")

// SharedSocket is a net.PacketConn that initiates two raw sockets (ipv4 and ipv6) and listens to UDP packets filtered
// by BPF instructions (e.g., IncomingSTUNFilter that checks and sends only STUN packets to the listeners (ReadFrom)).
// It is meant to be used when sharing a port with some other process.
type SharedSocket struct {
	ctx         context.Context
	conn4       *socket.Conn
	conn6       *socket.Conn
	probe4      *srcProbe
	probe6      *srcProbe
	port        int
	mtu         uint16
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

	rawSock.conn4, err = socket.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_UDP, "raw_udp4", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create ipv4 raw socket: %w", err)
	}

	if err = nbnet.SetSocketMark(rawSock.conn4); err != nil {
		return nil, fmt.Errorf("set SO_MARK on ipv4 socket: %w", err)
	}

	if rawSock.probe4, err = newSrcProbe(unix.AF_INET); err != nil {
		return nil, err
	}

	var sockErr error
	rawSock.conn6, sockErr = socket.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_UDP, "raw_udp6", nil)
	if sockErr != nil {
		log.Errorf("Failed to create ipv6 raw socket: %v", sockErr)
	} else {
		if err = nbnet.SetSocketMark(rawSock.conn6); err != nil {
			return nil, fmt.Errorf("set SO_MARK on ipv6 socket: %w", err)
		}
		rawSock.probe6, sockErr = newSrcProbe(unix.AF_INET6)
		if sockErr != nil {
			log.Errorf("Failed to create ipv6 source probe, continuing without ipv6: %v", sockErr)
			if closeErr := rawSock.conn6.Close(); closeErr != nil {
				log.Debugf("failed to close ipv6 raw socket: %v", closeErr)
			}
			rawSock.conn6 = nil
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

	return rawSock, nil
}

// sockaddr returns the raw send address for dst, carrying the scope of its zone.
func (s *SharedSocket) sockaddr(dst netip.Addr) (unix.Sockaddr, error) {
	if dst.Zone() == "" {
		return rawSockaddr(dst, 0), nil
	}
	if s.conn6 == nil {
		return nil, fmt.Errorf("no raw socket for %s", dst)
	}
	rc, err := s.conn6.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("ipv6 raw socket: %w", err)
	}
	scope, err := zoneIndex(rc, dst.Zone())
	if err != nil {
		return nil, err
	}
	return rawSockaddr(dst, scope), nil
}

// resolveSrc returns the source IP the kernel will pick for a packet sent to sa
// by these raw sockets, mirroring the fwmark the kernel will see on send.
func (s *SharedSocket) resolveSrc(dst netip.Addr, sa unix.Sockaddr) (netip.Addr, error) {
	probe := s.probe4
	if dst.Is6() {
		probe = s.probe6
	}
	if probe == nil {
		return netip.Addr{}, fmt.Errorf("no raw socket for %s", dst)
	}
	return probe.resolve(sa)
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

	if s.probe4 != nil {
		errGrp.Go(s.probe4.close)
	}
	if s.probe6 != nil {
		errGrp.Go(s.probe6.close)
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

	dst := rUDPAddr.AddrPort().Addr().Unmap()
	if !dst.IsValid() {
		return 0, fmt.Errorf("invalid destination %s", rUDPAddr)
	}

	rSockAddr, err := s.sockaddr(dst)
	if err != nil {
		return 0, err
	}

	src, err := s.resolveSrc(dst, rSockAddr)
	if err != nil {
		return 0, fmt.Errorf("resolve source for %s: %w", dst, err)
	}

	conn, nwLayer := s.getWriterObjects(src, dst)
	if conn == nil {
		return 0, fmt.Errorf("no raw socket for %s", dst)
	}

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
func (s *SharedSocket) getWriterObjects(src, dest netip.Addr) (conn *socket.Conn, layer gopacket.NetworkLayer) {
	if dest.Is6() {
		conn = s.conn6
		layer = &layers.IPv6{
			SrcIP: src.AsSlice(),
			DstIP: dest.AsSlice(),
		}
	} else {
		conn = s.conn4
		layer = &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
			SrcIP:    src.AsSlice(),
			DstIP:    dest.AsSlice(),
		}
	}

	return conn, layer
}
