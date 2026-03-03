package device

import (
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// PacketFilter interface for firewall abilities
type PacketFilter interface {
	// FilterOutbound filter outgoing packets from host to external destinations
	FilterOutbound(packetData []byte, size int) bool

	// FilterInbound filter incoming packets from external sources to host
	FilterInbound(packetData []byte, size int) bool

	// AddUDPPacketHook calls hook when UDP packet from given direction matched
	//
	// Hook function returns flag which indicates should be the matched package dropped or not.
	// Hook function receives raw network packet data as argument.
	AddUDPPacketHook(in bool, ip netip.Addr, dPort uint16, hook func(packet []byte) bool) string

	// RemovePacketHook removes hook by ID
	RemovePacketHook(hookID string) error
}

// FilteredDevice to override Read or Write of packets
type FilteredDevice struct {
	tun.Device

	filter    PacketFilter
	mutex     sync.RWMutex
	closeOnce sync.Once
}

// newDeviceFilter constructor function
func newDeviceFilter(device tun.Device) *FilteredDevice {
	return &FilteredDevice{
		Device: device,
	}
}

// Close closes the underlying tun device exactly once.
// wireguard-go's netTun.Close() panics on double-close due to a bare close(channel),
// and multiple code paths can trigger Close on the same device.
func (d *FilteredDevice) Close() error {
	var err error
	d.closeOnce.Do(func() {
		err = d.Device.Close()
	})
	if err != nil {
		return err
	}
	return nil
}

// Read wraps read method with filtering feature
func (d *FilteredDevice) Read(bufs [][]byte, sizes []int, offset int) (n int, err error) {
	if n, err = d.Device.Read(bufs, sizes, offset); err != nil {
		return 0, err
	}
	d.mutex.RLock()
	filter := d.filter
	d.mutex.RUnlock()

	if filter == nil {
		return
	}

	for i := 0; i < n; i++ {
		if filter.FilterOutbound(bufs[i][offset:offset+sizes[i]], sizes[i]) {
			bufs = append(bufs[:i], bufs[i+1:]...)
			sizes = append(sizes[:i], sizes[i+1:]...)
			n--
			i--
		}
	}

	return n, nil
}

// Write wraps write method with filtering feature
func (d *FilteredDevice) Write(bufs [][]byte, offset int) (int, error) {
	d.mutex.RLock()
	filter := d.filter
	d.mutex.RUnlock()

	if filter == nil {
		return d.Device.Write(bufs, offset)
	}

	filteredBufs := make([][]byte, 0, len(bufs))
	dropped := 0
	for _, buf := range bufs {
		if !filter.FilterInbound(buf[offset:], len(buf)) {
			filteredBufs = append(filteredBufs, buf)
			dropped++
		}
	}

	n, err := d.Device.Write(filteredBufs, offset)
	n += dropped
	return n, err
}

// SetFilter sets packet filter to device
func (d *FilteredDevice) SetFilter(filter PacketFilter) {
	d.mutex.Lock()
	d.filter = filter
	d.mutex.Unlock()
}
