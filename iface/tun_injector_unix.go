package iface

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.zx2c4.com/wireguard/tun"
)

// Injector interface to override Read or Write of packages
type Injector interface {
	// SkipReadPacket to skip reading of packets
	SkipReadPacket(packet gopacket.Packet) bool

	// SkipWritePacket to skip writing of packets
	SkipWritePacket(packet gopacket.Packet) bool
}

// TunInjection to override Read or Write of packages
type TunInjection struct {
	tun.Device
	injectors []Injector
}

// Read one or more packets from the Device (without any additional headers)
func (t *TunInjection) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
	// Call the original Read method
	if n, err = t.Device.Read(bufs, sizes, offset); err != nil {
		return 0, err
	}
	if len(t.injectors) == 0 {
		return
	}

	// Iterate over the read packets
	for i := 0; i < n; i++ {
		packetData := bufs[i][offset : offset+sizes[i]]
		packet := gopacket.NewPacket(packetData, layers.LayerTypeIPv4, gopacket.Default)

		// Check if the packet should be skipped
		shouldSkip := false
		for _, injector := range t.injectors {
			if injector.SkipReadPacket(packet) {
				shouldSkip = true
				break
			}
		}

		// If the packet should be skipped, remove it from the result
		if shouldSkip {
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
	if len(t.injectors) == 0 {
		return t.Device.Write(bufs, offset)
	}

	// Filter out packets that should be skipped
	filteredBufs := make([][]byte, 0, len(bufs))
	for _, buf := range bufs {
		packet := gopacket.NewPacket(buf[offset:], layers.LayerTypeIPv4, gopacket.Default)

		shouldSkip := false
		for _, injector := range t.injectors {
			if injector.SkipWritePacket(packet) {
				shouldSkip = true
				break
			}
		}

		// If the packet should not be skipped, add it to the filtered bufs
		if !shouldSkip {
			filteredBufs = append(filteredBufs, buf)
		}
	}

	// Call the original Write method with the filtered bufs
	return t.Device.Write(filteredBufs, offset)
}
