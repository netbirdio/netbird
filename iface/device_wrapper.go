package iface

import (
	"net"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// PacketFilter interface for firewall abilities
type PacketFilter interface {
	// DropInput traffic filter
	DropInput(packetData []byte) bool

	// DropOutput traffic filter
	DropOutput(packetData []byte) bool

	// SetNetwork of the wireguard interface to which filtering applied
	SetNetwork(*net.IPNet)
}

// DeviceWrapper to override Read or Write of packets
type DeviceWrapper struct {
	tun.Device
	filter PacketFilter
	mutex  sync.Mutex
}

// newDeviceWrapper constructor function
func newDeviceWrapper(device tun.Device) *DeviceWrapper {
	return &DeviceWrapper{
		Device: device,
	}
}

// Read wraps read method with filtering feature
func (d *DeviceWrapper) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
	if n, err = d.Device.Read(bufs, sizes, offset); err != nil {
		return 0, err
	}
	d.mutex.Lock()
	filter := d.filter
	d.mutex.Unlock()

	if filter == nil {
		return
	}

	for i := 0; i < n; i++ {
		if filter.DropInput(bufs[i][offset : offset+sizes[i]]) {
			bufs = append(bufs[:i], bufs[i+1:]...)
			sizes = append(sizes[:i], sizes[i+1:]...)
			n--
			i--
		}
	}

	return n, nil
}

// Write wraps write method with filtering feature
func (d *DeviceWrapper) Write(bufs [][]byte, offset int) (int, error) {
	d.mutex.Lock()
	filter := d.filter
	d.mutex.Unlock()

	if filter == nil {
		return d.Device.Write(bufs, offset)
	}

	filteredBufs := make([][]byte, 0, len(bufs))
	dropped := 0
	for _, buf := range bufs {
		if !filter.DropOutput(buf[offset:]) {
			filteredBufs = append(filteredBufs, buf)
			dropped++
		}
	}

	n, err := d.Device.Write(filteredBufs, offset)
	n += dropped
	return n, err
}

// SetFiltering sets packet filter to device
func (d *DeviceWrapper) SetFiltering(filter PacketFilter) {
	d.mutex.Lock()
	d.filter = filter
	d.mutex.Unlock()
}
