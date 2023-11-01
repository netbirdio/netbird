package iface

import (
	"net"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	mocks "github.com/netbirdio/netbird/iface/mocks"
)

func TestDeviceWrapperRead(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("read ICMP", func(t *testing.T) {
		ipLayer := &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolICMPv4,
			SrcIP:    net.IP{192, 168, 0, 1},
			DstIP:    net.IP{100, 200, 0, 1},
		}

		icmpLayer := &layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
			Id:       1,
			Seq:      1,
		}

		buffer := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{},
			ipLayer,
			icmpLayer,
		)
		if err != nil {
			t.Errorf("serialize packet: %v", err)
			return
		}

		mockBufs := [][]byte{{}}
		mockSizes := []int{0}
		mockOffset := 0

		tun := mocks.NewMockDevice(ctrl)
		tun.EXPECT().Read(mockBufs, mockSizes, mockOffset).
			DoAndReturn(func(bufs [][]byte, sizes []int, offset int) (int, error) {
				bufs[0] = buffer.Bytes()
				sizes[0] = len(bufs[0])
				return 1, nil
			})

		wrapped := newDeviceWrapper(tun)

		bufs := [][]byte{{}}
		sizes := []int{0}
		offset := 0

		n, err := wrapped.Read(bufs, sizes, offset)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}
		if n != 1 {
			t.Errorf("expected n=1, got %d", n)
			return
		}
	})

	t.Run("write TCP", func(t *testing.T) {
		ipLayer := &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolICMPv4,
			SrcIP:    net.IP{100, 200, 0, 9},
			DstIP:    net.IP{100, 200, 0, 10},
		}

		// create TCP layer packet
		tcpLayer := &layers.TCP{
			SrcPort: layers.TCPPort(34423),
			DstPort: layers.TCPPort(8080),
		}

		buffer := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{},
			ipLayer,
			tcpLayer,
		)
		if err != nil {
			t.Errorf("serialize packet: %v", err)
			return
		}

		mockBufs := [][]byte{buffer.Bytes()}

		mockBufs[0] = buffer.Bytes()
		tun := mocks.NewMockDevice(ctrl)
		tun.EXPECT().Write(mockBufs, 0).Return(1, nil)

		wrapped := newDeviceWrapper(tun)

		bufs := [][]byte{buffer.Bytes()}

		n, err := wrapped.Write(bufs, 0)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}
		if n != 1 {
			t.Errorf("expected n=1, got %d", n)
			return
		}
	})

	t.Run("drop write UDP package", func(t *testing.T) {
		ipLayer := &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolICMPv4,
			SrcIP:    net.IP{100, 200, 0, 11},
			DstIP:    net.IP{100, 200, 0, 20},
		}

		// create TCP layer packet
		tcpLayer := &layers.UDP{
			SrcPort: layers.UDPPort(27278),
			DstPort: layers.UDPPort(53),
		}

		buffer := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{},
			ipLayer,
			tcpLayer,
		)
		if err != nil {
			t.Errorf("serialize packet: %v", err)
			return
		}

		mockBufs := [][]byte{}

		tun := mocks.NewMockDevice(ctrl)
		tun.EXPECT().Write(mockBufs, 0).Return(0, nil)

		filter := mocks.NewMockPacketFilter(ctrl)
		filter.EXPECT().DropIncoming(gomock.Any()).Return(true)

		wrapped := newDeviceWrapper(tun)
		wrapped.filter = filter

		bufs := [][]byte{buffer.Bytes()}

		n, err := wrapped.Write(bufs, 0)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}
		if n != 0 {
			t.Errorf("expected n=1, got %d", n)
			return
		}
	})

	t.Run("drop read UDP package", func(t *testing.T) {
		ipLayer := &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolICMPv4,
			SrcIP:    net.IP{100, 200, 0, 11},
			DstIP:    net.IP{100, 200, 0, 20},
		}

		// create TCP layer packet
		tcpLayer := &layers.UDP{
			SrcPort: layers.UDPPort(19243),
			DstPort: layers.UDPPort(1024),
		}

		buffer := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{},
			ipLayer,
			tcpLayer,
		)
		if err != nil {
			t.Errorf("serialize packet: %v", err)
			return
		}

		mockBufs := [][]byte{{}}
		mockSizes := []int{0}
		mockOffset := 0

		tun := mocks.NewMockDevice(ctrl)
		tun.EXPECT().Read(mockBufs, mockSizes, mockOffset).
			DoAndReturn(func(bufs [][]byte, sizes []int, offset int) (int, error) {
				bufs[0] = buffer.Bytes()
				sizes[0] = len(bufs[0])
				return 1, nil
			})
		filter := mocks.NewMockPacketFilter(ctrl)
		filter.EXPECT().DropOutgoing(gomock.Any()).Return(true)

		wrapped := newDeviceWrapper(tun)
		wrapped.filter = filter

		bufs := [][]byte{{}}
		sizes := []int{0}
		offset := 0

		n, err := wrapped.Read(bufs, sizes, offset)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}
		if n != 0 {
			t.Errorf("expected n=0, got %d", n)
			return
		}
	})
}
