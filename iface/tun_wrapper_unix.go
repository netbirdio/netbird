package iface

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.zx2c4.com/wireguard/tun"
)

// PacketFilter interface for firewall abilities
type PacketFilter interface {
	// DropInput traffic filter
	DropInput(packet gopacket.Packet) bool

	// DropOutput traffic filter
	DropOutput(packet gopacket.Packet) bool
}

// TunWrapper to override Read or Write of packets
type TunWrapper struct {
	tun.Device
	filter PacketFilter
}

// newTunInjection constructor function
func newTunInjection(device tun.Device) *TunWrapper {
	return &TunWrapper{
		Device: device,
	}
}

// Read wraps read method with filtering feature
func (t *TunWrapper) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
	if n, err = t.Device.Read(bufs, sizes, offset); err != nil {
		return 0, err
	}
	if t.filter == nil {
		return
	}

	for i := 0; i < n; i++ {
		packetData := bufs[i][offset : offset+sizes[i]]
		packet := gopacket.NewPacket(packetData, layers.LayerTypeIPv4, gopacket.Default)

		if t.filter.DropInput(packet) {
			bufs = append(bufs[:i], bufs[i+1:]...)
			sizes = append(sizes[:i], sizes[i+1:]...)
			n--
			i--
		}
	}

	return n, nil
}

// Write wraps write method with filtering feature
func (t *TunWrapper) Write(bufs [][]byte, offset int) (int, error) {
	if t.filter == nil {
		return t.Device.Write(bufs, offset)
	}

	filteredBufs := make([][]byte, 0, len(bufs))
	dropped := 0
	for _, buf := range bufs {
		// TODO: handle IPv6 packets
		packet := gopacket.NewPacket(buf[offset:], layers.LayerTypeIPv4, gopacket.Default)

		if !t.filter.DropOutput(packet) {
			filteredBufs = append(filteredBufs, buf)
			dropped++
		}
	}

	n, err := t.Device.Write(filteredBufs, offset)
	n += dropped
	return n, err
}
