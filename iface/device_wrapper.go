package iface

import (
	"golang.zx2c4.com/wireguard/tun"
)

// PacketFilter interface for firewall abilities
type PacketFilter interface {
	// DropInput traffic filter
	DropInput(packetData []byte) bool

	// DropOutput traffic filter
	DropOutput(packetData []byte) bool
}

// DeviceWrapper to override Read or Write of packets
type DeviceWrapper struct {
	tun.Device
	filter PacketFilter
}

// newDeviceWrapper constructor function
func newDeviceWrapper(device tun.Device) *DeviceWrapper {
	return &DeviceWrapper{
		Device: device,
	}
}

// Read wraps read method with filtering feature
func (t *DeviceWrapper) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
	if n, err = t.Device.Read(bufs, sizes, offset); err != nil {
		return 0, err
	}
	if t.filter == nil {
		return
	}

	for i := 0; i < n; i++ {
		if t.filter.DropInput(bufs[i][offset : offset+sizes[i]]) {
			bufs = append(bufs[:i], bufs[i+1:]...)
			sizes = append(sizes[:i], sizes[i+1:]...)
			n--
			i--
		}
	}

	return n, nil
}

// Write wraps write method with filtering feature
func (t *DeviceWrapper) Write(bufs [][]byte, offset int) (int, error) {
	if t.filter == nil {
		return t.Device.Write(bufs, offset)
	}

	filteredBufs := make([][]byte, 0, len(bufs))
	dropped := 0
	for _, buf := range bufs {
		if !t.filter.DropOutput(buf[offset:]) {
			filteredBufs = append(filteredBufs, buf)
			dropped++
		}
	}

	n, err := t.Device.Write(filteredBufs, offset)
	n += dropped
	return n, err
}
