package device

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"go.uber.org/mock/gomock"

	mocks "github.com/netbirdio/netbird/client/iface/mocks"
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

		wrapped := newDeviceFilter(tun)

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

		wrapped := newDeviceFilter(tun)

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
		filter.EXPECT().FilterInbound(gomock.Any(), gomock.Any()).Return(true)

		wrapped := newDeviceFilter(tun)
		wrapped.filter = filter

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
		filter.EXPECT().FilterOutbound(gomock.Any(), gomock.Any()).Return(true)

		wrapped := newDeviceFilter(tun)
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

// TestDeviceWrapperReadKeepsCallerBuffers checks that dropping packets from a
// batch compacts the packet data without moving the caller's buffers:
// wireguard-go reuses the same bufs slice for every read and pairs bufs[i]
// with its own outbound element, so the kept packets must be returned in
// order while every entry of bufs keeps pointing at the same memory.
func TestDeviceWrapperReadKeepsCallerBuffers(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	const offset = 4
	packets := []string{"drop", "first kept", "drop", "second kept", "drop"}
	kept := []string{"first kept", "second kept"}

	tun := mocks.NewMockDevice(ctrl)
	tun.EXPECT().Read(gomock.Any(), gomock.Any(), offset).
		DoAndReturn(func(bufs [][]byte, sizes []int, offset int) (int, error) {
			for i, packet := range packets {
				sizes[i] = copy(bufs[i][offset:], packet)
			}
			return len(packets), nil
		})
	filter := mocks.NewMockPacketFilter(ctrl)
	filter.EXPECT().FilterOutbound(gomock.Any(), gomock.Any()).
		DoAndReturn(func(packet []byte, _ int) bool { return string(packet) == "drop" }).
		Times(len(packets))

	wrapped := newDeviceFilter(tun)
	wrapped.filter = filter

	bufs := make([][]byte, len(packets)+1)
	before := make([]*byte, len(bufs))
	for i := range bufs {
		bufs[i] = make([]byte, 32)
		before[i] = &bufs[i][0]
	}
	sizes := make([]int, len(bufs))

	n, err := wrapped.Read(bufs, sizes, offset)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(kept) {
		t.Fatalf("expected n=%d, got %d", len(kept), n)
	}
	for i, want := range kept {
		if got := string(bufs[i][offset : offset+sizes[i]]); got != want {
			t.Errorf("packet %d: expected %q, got %q", i, want, got)
		}
	}
	for i := range bufs {
		if &bufs[i][0] != before[i] {
			t.Errorf("caller's buffer %d was moved", i)
		}
	}
}

func TestDeviceWrapperReadPanic(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tun := mocks.NewMockDevice(ctrl)
	tun.EXPECT().Read(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(bufs [][]byte, sizes []int, offset int) (int, error) {
			// Reproduce the wintun zero-length packet panic (index out of range).
			packet := make([]byte, 0)
			return int(packet[0]), nil
		})

	wrapped := newDeviceFilter(tun)

	handlerCalled := false
	wrapped.SetPanicHandler(func() { handlerCalled = true })

	n, err := wrapped.Read([][]byte{{}}, []int{0}, 0)
	if err == nil {
		t.Errorf("expected error from recovered panic, got nil")
	}
	if n != 0 {
		t.Errorf("expected n=0, got %d", n)
	}
	if !handlerCalled {
		t.Errorf("expected panic handler to be called")
	}
}

func TestDeviceWrapperWritePanic(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tun := mocks.NewMockDevice(ctrl)
	tun.EXPECT().Write(gomock.Any(), gomock.Any()).
		DoAndReturn(func(bufs [][]byte, offset int) (int, error) {
			packet := make([]byte, 0)
			return int(packet[0]), nil
		})

	wrapped := newDeviceFilter(tun)

	handlerCalled := false
	wrapped.SetPanicHandler(func() { handlerCalled = true })

	n, err := wrapped.Write([][]byte{{0x45, 0x00}}, 0)
	if err == nil {
		t.Errorf("expected error from recovered panic, got nil")
	}
	if n != 0 {
		t.Errorf("expected n=0, got %d", n)
	}
	if !handlerCalled {
		t.Errorf("expected panic handler to be called")
	}
}
