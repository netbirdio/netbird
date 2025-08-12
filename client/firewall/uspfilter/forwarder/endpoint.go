package forwarder

import (
	"fmt"

	wgdevice "golang.zx2c4.com/wireguard/device"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
)

// endpoint implements stack.LinkEndpoint and handles integration with the wireguard device
type endpoint struct {
	logger     *nblog.Logger
	dispatcher stack.NetworkDispatcher
	device     *wgdevice.Device
	mtu        uint32
}

func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
}

func (e *endpoint) IsAttached() bool {
	return e.dispatcher != nil
}

func (e *endpoint) MTU() uint32 {
	return e.mtu
}

func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}

func (e *endpoint) MaxHeaderLength() uint16 {
	return 0
}

func (e *endpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (e *endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	var written int
	for _, pkt := range pkts.AsSlice() {
		netHeader := header.IPv4(pkt.NetworkHeader().View().AsSlice())

		data := stack.PayloadSince(pkt.NetworkHeader())
		if data == nil {
			continue
		}

		// Send the packet through WireGuard
		address := netHeader.DestinationAddress()
		err := e.device.CreateOutboundPacket(data.AsSlice(), address.AsSlice())
		if err != nil {
			e.logger.Error1("CreateOutboundPacket: %v", err)
			continue
		}
		written++
	}

	return written, nil
}

func (e *endpoint) Wait() {
	// not required
}

func (e *endpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (e *endpoint) AddHeader(*stack.PacketBuffer) {
	// not required
}

func (e *endpoint) ParseHeader(*stack.PacketBuffer) bool {
	return true
}

type epID stack.TransportEndpointID

func (i epID) String() string {
	// src and remote is swapped
	return fmt.Sprintf("%s:%d → %s:%d", i.RemoteAddress, i.RemotePort, i.LocalAddress, i.LocalPort)
}
