//go:build linux && !android

package udp

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/wgproxy/rawsocket"
)

var (
	serializeOpts = gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	localHostNetIPAddrV4 = &net.IPAddr{
		IP: net.ParseIP("127.0.0.1"),
	}
	localHostNetIPAddrV6 = &net.IPAddr{
		IP: net.ParseIP("::1"),
	}
)

type SrcFaker struct {
	srcAddr *net.UDPAddr

	rawSocket     net.PacketConn
	ipH           gopacket.SerializableLayer
	udpH          gopacket.SerializableLayer
	layerBuffer   gopacket.SerializeBuffer
	localHostAddr *net.IPAddr
}

func NewSrcFaker(dstPort int, srcAddr *net.UDPAddr) (*SrcFaker, error) {
	rawSocket, err := rawsocket.PrepareSenderRawSocket()
	if err != nil {
		return nil, err
	}

	ipH, udpH, err := prepareHeaders(dstPort, srcAddr)
	if err != nil {
		return nil, err
	}

	localHostAddr := localHostNetIPAddrV4
	if srcAddr.IP.To4() == nil {
		localHostAddr = localHostNetIPAddrV6
	}

	f := &SrcFaker{
		srcAddr:       srcAddr,
		rawSocket:     rawSocket,
		ipH:           ipH,
		udpH:          udpH,
		layerBuffer:   gopacket.NewSerializeBuffer(),
		localHostAddr: localHostAddr,
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
	n, err := f.rawSocket.WriteTo(f.layerBuffer.Bytes(), f.localHostAddr)
	if err != nil {
		return 0, fmt.Errorf("write to raw conn: %w", err)
	}
	return n, nil
}

func prepareHeaders(dstPort int, srcAddr *net.UDPAddr) (gopacket.SerializableLayer, gopacket.SerializableLayer, error) {
	var ipH gopacket.SerializableLayer
	var networkLayer gopacket.NetworkLayer

	// Check if source IP is IPv4 or IPv6
	if srcAddr.IP.To4() != nil {
		// IPv4
		ipv4 := &layers.IPv4{
			DstIP:    net.ParseIP("127.0.0.1"),
			SrcIP:    srcAddr.IP,
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolUDP,
		}
		ipH = ipv4
		networkLayer = ipv4
	} else {
		// IPv6
		ipv6 := &layers.IPv6{
			DstIP:      net.ParseIP("::1"),
			SrcIP:      srcAddr.IP,
			Version:    6,
			HopLimit:   64,
			NextHeader: layers.IPProtocolUDP,
		}
		ipH = ipv6
		networkLayer = ipv6
	}

	udpH := &layers.UDP{
		SrcPort: layers.UDPPort(srcAddr.Port),
		DstPort: layers.UDPPort(dstPort), // dst is the localhost WireGuard port
	}

	err := udpH.SetNetworkLayerForChecksum(networkLayer)
	if err != nil {
		return nil, nil, fmt.Errorf("set network layer for checksum: %w", err)
	}

	return ipH, udpH, nil
}
