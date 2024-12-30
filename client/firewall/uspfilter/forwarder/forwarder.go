package forwarder

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/common"
)

const (
	receiveWindow = 32768
	maxInFlight   = 1024
)

type Forwarder struct {
	stack        *stack.Stack
	endpoint     *endpoint
	udpForwarder *udpForwarder
	ctx          context.Context
	cancel       context.CancelFunc
}

func New(iface common.IFaceMapper) (*Forwarder, error) {

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
		HandleLocal: false,
	})

	mtu, err := iface.GetDevice().MTU()
	if err != nil {
		return nil, fmt.Errorf("get MTU: %w", err)
	}
	nicID := tcpip.NICID(1)
	endpoint := &endpoint{
		device: iface.GetWGDevice(),
		mtu:    uint32(mtu),
	}

	if err := s.CreateNIC(nicID, endpoint); err != nil {
		return nil, fmt.Errorf("failed to create NIC: %w", err)
	}

	_, bits := iface.Address().Network.Mask.Size()
	protoAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(iface.Address().IP.To4()),
			PrefixLen: bits,
		},
	}

	if err := s.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("failed to add protocol address: %w", err)
	}

	defaultSubnet, err := tcpip.NewSubnet(
		tcpip.AddrFrom4([4]byte{0, 0, 0, 0}),
		tcpip.MaskFromBytes([]byte{0, 0, 0, 0}),
	)
	if err != nil {
		return nil, fmt.Errorf("creating default subnet: %w", err)
	}

	if s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("set promiscuous mode: %w", err)
	}
	if s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("set spoofing: %w", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{
			Destination: defaultSubnet,
			NIC:         nicID,
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	f := &Forwarder{
		stack:        s,
		endpoint:     endpoint,
		udpForwarder: newUDPForwarder(),
		ctx:          ctx,
		cancel:       cancel,
	}

	// Set up TCP forwarder
	tcpForwarder := tcp.NewForwarder(s, receiveWindow, maxInFlight, f.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	// Set up UDP forwarder
	udpForwarder := udp.NewForwarder(s, f.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

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
func (f *Forwarder) Stop() error {
	f.cancel()

	if f.udpForwarder != nil {
		f.udpForwarder.Stop()
	}

	f.stack.Close()
	f.stack.Wait()

	return nil
}
