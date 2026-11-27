package device

import (
	"net"
	"net/netip"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	mocks "github.com/netbirdio/netbird/client/iface/mocks"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
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

func TestDeviceWrapperReadLoopsBackToSelf(t *testing.T) {
	self, err := wgaddr.ParseWGAddress("100.64.0.1/16")
	require.NoError(t, err)
	v4Only := self
	self.IPv6 = netip.MustParseAddr("fd00::1")
	self.IPv6Net = netip.MustParsePrefix("fd00::/64")

	// Packets read from the device were sent by the local host, so a packet to self
	// carries the own address as both source and destination.
	packet := func(t *testing.T, addr net.IP) []byte {
		var ipLayer gopacket.SerializableLayer = &layers.IPv4{
			Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: addr, DstIP: addr,
		}
		if addr.To4() == nil {
			ipLayer = &layers.IPv6{
				Version: 6, HopLimit: 64, NextHeader: layers.IPProtocolUDP, SrcIP: addr, DstIP: addr,
			}
		}
		buf := gopacket.NewSerializeBuffer()
		err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
			ipLayer, &layers.UDP{SrcPort: 1234, DstPort: 5678})
		require.NoError(t, err)
		return buf.Bytes()
	}

	tests := []struct {
		name     string
		self     *wgaddr.Address
		dst      string
		loopBack bool
	}{
		{name: "v4 to self", self: &self, dst: "100.64.0.1", loopBack: true},
		{name: "v6 to self", self: &self, dst: "fd00::1", loopBack: true},
		{name: "v4 to peer", self: &self, dst: "100.64.0.2"},
		{name: "v6 to peer", self: &self, dst: "fd00::2"},
		{name: "v4 to self without self address", dst: "100.64.0.1"},
		{name: "v6 to self without own v6", self: &v4Only, dst: "fd00::1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			pkt := packet(t, net.ParseIP(tc.dst))

			// The darwin TUN writes its 4-byte AF header in front of offset.
			const offset = 4
			tun := mocks.NewMockDevice(ctrl)
			tun.EXPECT().Read(gomock.Any(), gomock.Any(), offset).
				DoAndReturn(func(bufs [][]byte, sizes []int, offset int) (int, error) {
					sizes[0] = copy(bufs[0][offset:], pkt)
					return 1, nil
				})

			var written [][]byte
			if tc.loopBack {
				tun.EXPECT().Write(gomock.Any(), offset).
					DoAndReturn(func(bufs [][]byte, offset int) (int, error) {
						written = append(written, bufs[0][offset:])
						return 1, nil
					})
			}

			wrapped := newDeviceFilter(tun)
			if tc.self != nil {
				wrapped.setSelfAddr(*tc.self)
			}

			n, err := wrapped.Read([][]byte{make([]byte, 1500)}, []int{0}, offset)
			require.NoError(t, err)

			if !tc.loopBack {
				assert.Equal(t, 1, n, "packet should be passed on to the overlay")
				return
			}
			assert.Equal(t, 0, n, "packet to self should not be passed on to the overlay")
			require.Len(t, written, 1, "packet to self should be written back to the device")
			assert.Equal(t, pkt, written[0], "packet should be written back unchanged")
		})
	}
}

func TestIsToSelfMalformed(t *testing.T) {
	self, err := wgaddr.ParseWGAddress("100.64.0.1/16")
	require.NoError(t, err)

	// Reading the destination of a too-short packet would panic outside the
	// device's panic recovery and take down the daemon.
	for _, pkt := range [][]byte{nil, {0x45}, {0x60, 0, 0, 0}} {
		assert.False(t, isToSelf(pkt, self), "malformed packet %x must not match", pkt)
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
