package udp

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"

	nbnet "github.com/netbirdio/netbird/util/net"
)

var (
	serializeOpts = gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	localHostNetIPAddr = &net.IPAddr{
		IP: net.ParseIP("127.0.0.1"),
	}
)

type SrcFaker struct {
	srcAddr *net.UDPAddr

	rawSocket   net.PacketConn
	ipH         gopacket.SerializableLayer
	udpH        gopacket.SerializableLayer
	layerBuffer gopacket.SerializeBuffer
}

func NewSrcFaker(dstPort int, srcAddr *net.UDPAddr) (*SrcFaker, error) {
	rawSocket, err := prepareSenderRawSocket()
	if err != nil {
		return nil, err
	}

	ipH, udpH, err := prepareHeaders(dstPort, srcAddr)
	if err != nil {
		return nil, err
	}

	f := &SrcFaker{
		srcAddr:     srcAddr,
		rawSocket:   rawSocket,
		ipH:         ipH,
		udpH:        udpH,
		layerBuffer: gopacket.NewSerializeBuffer(),
	}

	return f, nil
}

func (f *SrcFaker) Close() error {
	return f.rawSocket.Close()
}

func (f *SrcFaker) SendPkg(data []byte) (int, error) {
	defer func() {
		if err := f.layerBuffer.Clear(); err != nil {
			log.Errorf("failed to clear layer buffer: %s", err)
		}
	}()

	payload := gopacket.Payload(data)

	err := gopacket.SerializeLayers(f.layerBuffer, serializeOpts, f.ipH, f.udpH, payload)
	if err != nil {
		return 0, fmt.Errorf("serialize layers: %w", err)
	}
	n, err := f.rawSocket.WriteTo(f.layerBuffer.Bytes(), localHostNetIPAddr)
	if err != nil {
		return 0, fmt.Errorf("write to raw conn: %w", err)
	}
	return n, nil
}

func prepareHeaders(dstPort int, srcAddr *net.UDPAddr) (gopacket.SerializableLayer, gopacket.SerializableLayer, error) {
	ipH := &layers.IPv4{
		DstIP:    net.ParseIP("127.0.0.1"),
		SrcIP:    srcAddr.IP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
	}
	udpH := &layers.UDP{
		SrcPort: layers.UDPPort(srcAddr.Port),
		DstPort: layers.UDPPort(dstPort), // dst is the localhost WireGuard port
	}

	err := udpH.SetNetworkLayerForChecksum(ipH)
	if err != nil {
		return nil, nil, fmt.Errorf("set network layer for checksum: %w", err)
	}

	return ipH, udpH, nil
}

func prepareSenderRawSocket() (net.PacketConn, error) {
	// Create a raw socket.
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("creating raw socket failed: %w", err)
	}

	// Set the IP_HDRINCL option on the socket to tell the kernel that headers are included in the packet.
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		return nil, fmt.Errorf("setting IP_HDRINCL failed: %w", err)
	}

	// Bind the socket to the "lo" interface.
	err = syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, "lo")
	if err != nil {
		return nil, fmt.Errorf("binding to lo interface failed: %w", err)
	}

	// Set the fwmark on the socket.
	err = nbnet.SetSocketOpt(fd)
	if err != nil {
		return nil, fmt.Errorf("setting fwmark failed: %w", err)
	}

	// Convert the file descriptor to a PacketConn.
	file := os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd))
	if file == nil {
		return nil, fmt.Errorf("converting fd to file failed")
	}
	packetConn, err := net.FilePacketConn(file)
	if err != nil {
		return nil, fmt.Errorf("converting file to packet conn failed: %w", err)
	}

	return packetConn, nil
}
