package forwarder

import (
	"context"
	"fmt"
	"net"
	"runtime"

	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/common"
	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
)

const (
	defaultReceiveWindow = 32768
	defaultMaxInFlight   = 1024
	iosReceiveWindow     = 16384
	iosMaxInFlight       = 256
)

type Forwarder struct {
	logger       *nblog.Logger
	stack        *stack.Stack
	endpoint     *endpoint
	udpForwarder *udpForwarder
	ctx          context.Context
	cancel       context.CancelFunc
	ip           net.IP
	netstack     bool
}

func New(iface common.IFaceMapper, logger *nblog.Logger, netstack bool) (*Forwarder, error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
		},
		HandleLocal: false,
	})

	mtu, err := iface.GetDevice().MTU()
	if err != nil {
		return nil, fmt.Errorf("get MTU: %w", err)
	}
	nicID := tcpip.NICID(1)
	endpoint := &endpoint{
		logger: logger,
		device: iface.GetWGDevice(),
		mtu:    uint32(mtu),
	}

	if err := s.CreateNIC(nicID, endpoint); err != nil {
		return nil, fmt.Errorf("failed to create NIC: %v", err)
	}

	ones, _ := iface.Address().Network.Mask.Size()
	protoAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(iface.Address().IP.To4()),
			PrefixLen: ones,
		},
	}

	if err := s.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("failed to add protocol address: %s", err)
	}

	defaultSubnet, err := tcpip.NewSubnet(
		tcpip.AddrFrom4([4]byte{0, 0, 0, 0}),
		tcpip.MaskFromBytes([]byte{0, 0, 0, 0}),
	)
	if err != nil {
		return nil, fmt.Errorf("creating default subnet: %w", err)
	}

	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("set promiscuous mode: %s", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("set spoofing: %s", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{
			Destination: defaultSubnet,
			NIC:         nicID,
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	f := &Forwarder{
		logger:       logger,
		stack:        s,
		endpoint:     endpoint,
		udpForwarder: newUDPForwarder(mtu, logger),
		ctx:          ctx,
		cancel:       cancel,
		netstack:     netstack,
		ip:           iface.Address().IP,
	}

	receiveWindow := defaultReceiveWindow
	maxInFlight := defaultMaxInFlight
	if runtime.GOOS == "ios" {
		receiveWindow = iosReceiveWindow
		maxInFlight = iosMaxInFlight
	}

	tcpForwarder := tcp.NewForwarder(s, receiveWindow, maxInFlight, f.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	udpForwarder := udp.NewForwarder(s, f.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	s.SetTransportProtocolHandler(icmp.ProtocolNumber4, f.handleICMP)

	log.Debugf("forwarder: Initialization complete with NIC %d", nicID)
	return f, nil
}

func (f *Forwarder) InjectIncomingPacket(payload []byte) error {
	if len(payload) < header.IPv4MinimumSize {
		return fmt.Errorf("packet too small: %d bytes", len(payload))
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(payload),
	})
	defer pkt.DecRef()

	if f.endpoint.dispatcher != nil {
		f.endpoint.dispatcher.DeliverNetworkPacket(ipv4.ProtocolNumber, pkt)
	}
	return nil
}

// Stop gracefully shuts down the forwarder
func (f *Forwarder) Stop() {
	f.cancel()

	if f.udpForwarder != nil {
		f.udpForwarder.Stop()
	}

	f.stack.Close()
	f.stack.Wait()
}

func (f *Forwarder) determineDialAddr(addr tcpip.Address) net.IP {
	if f.netstack && f.ip.Equal(addr.AsSlice()) {
		return net.IPv4(127, 0, 0, 1)
	}
	return addr.AsSlice()
}
