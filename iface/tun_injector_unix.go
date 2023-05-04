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

	// DropOutput traffice filter
	DropOutput(packet gopacket.Packet) bool
}

// TunInjection to override Read or Write of packages
type TunInjection struct {
	tun.Device
	filters []PacketFilter
}

// newTunInjection constructor function
func newTunInjection(device tun.Device, filters []PacketFilter) *TunInjection {
	return &TunInjection{
		Device:  device,
		filters: filters,
	}
}

// Read one or more packets from the Device (without any additional headers)
func (t *TunInjection) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
	// Call the original Read method
	if n, err = t.Device.Read(bufs, sizes, offset); err != nil {
		return 0, err
	}
	println(">>>>", bufs[0])
	if len(t.filters) == 0 {
		return
	}

	// Iterate over the read packets
	for i := 0; i < n; i++ {
		packetData := bufs[i][offset : offset+sizes[i]]
		packet := gopacket.NewPacket(packetData, layers.LayerTypeIPv4, gopacket.Default)

		// Check if the packet should be skipped
		shouldDropped := false
		for _, injector := range t.filters {
			if injector.DropInput(packet) {
				shouldDropped = true
				break
			}
		}

		// If the packet should be skipped, remove it from the result
		if shouldDropped {
			bufs = append(bufs[:i], bufs[i+1:]...)
			sizes = append(sizes[:i], sizes[i+1:]...)
			n--
			i--
		}
	}

	return n, nil
}

// Write wraps write method for TunInjection
func (t *TunInjection) Write(bufs [][]byte, offset int) (int, error) {
	if len(t.filters) == 0 {
		println("<<<<", bufs[0])
		return t.Device.Write(bufs, offset)
	}

	// Filter out packets that should be skipped
	filteredBufs := make([][]byte, 0, len(bufs))
	for _, buf := range bufs {
		packet := gopacket.NewPacket(buf[offset:], layers.LayerTypeIPv4, gopacket.Default)

		shouldDropped := false
		for _, injector := range t.filters {
			if injector.DropOutput(packet) {
				shouldDropped = true
				break
			}
		}

		// If the packet should not be skipped, add it to the filtered bufs
		if !shouldDropped {
			filteredBufs = append(filteredBufs, buf)
		}
	}

	// Call the original Write method with the filtered bufs
	return t.Device.Write(filteredBufs, offset)
}
