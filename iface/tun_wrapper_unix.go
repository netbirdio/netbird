package iface

import (
	"os"

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
	device tun.Device
	filter PacketFilter
}

// newTunInjection constructor function
func newTunInjection(device tun.Device) *TunWrapper {
	return &TunWrapper{
		device: device,
	}
}

// Read wraps read method with filtering feature
func (t *TunWrapper) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
	if n, err = t.device.Read(bufs, sizes, offset); err != nil {
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
		return t.device.Write(bufs, offset)
	}

	filteredBufs := make([][]byte, 0, len(bufs))
	for _, buf := range bufs {
		// TODO: handle IPv6 packets
		packet := gopacket.NewPacket(buf[offset:], layers.LayerTypeIPv4, gopacket.Default)

		if !t.filter.DropOutput(packet) {
			filteredBufs = append(filteredBufs, buf)
		}
	}

	return t.device.Write(filteredBufs, offset)
}

// File returns the file descriptor of the device.
func (t *TunWrapper) File() *os.File {
	return t.device.File()
}

// MTU returns the MTU of the Device.
func (t *TunWrapper) MTU() (int, error) {
	return t.device.MTU()
}

// Name returns the current name of the Device.
func (t *TunWrapper) Name() (string, error) {
	return t.device.Name()
}

// Events returns a channel of type Event, which is fed Device events.
func (t *TunWrapper) Events() <-chan tun.Event {
	return t.device.Events()
}

// Close stops the Device and closes the Event channel.
func (t *TunWrapper) Close() error {
	return t.device.Close()
}

// BatchSize returns the preferred/max number of packets that can be read or
// written in a single read/write call. BatchSize must not change over the
// lifetime of a Device.
func (t *TunWrapper) BatchSize() int {
	return t.device.BatchSize()
}
