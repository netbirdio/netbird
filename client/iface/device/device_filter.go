package device

import (
	"net/netip"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"
)

// PacketFilter interface for firewall abilities
type PacketFilter interface {
	// FilterOutbound filter outgoing packets from host to external destinations
	FilterOutbound(packetData []byte, size int) bool

	// FilterInbound filter incoming packets from external sources to host
	FilterInbound(packetData []byte, size int) bool

	// SetUDPPacketHook registers a hook for outbound UDP packets matching the given IP and port.
	// Hook function returns true if the packet should be dropped.
	// Only one UDP hook is supported; calling again replaces the previous hook.
	// Pass nil hook to remove.
	SetUDPPacketHook(ip netip.Addr, dPort uint16, hook func(packet []byte) bool)

	// SetTCPPacketHook registers a hook for outbound TCP packets matching the given IP and port.
	// Hook function returns true if the packet should be dropped.
	// Only one TCP hook is supported; calling again replaces the previous hook.
	// Pass nil hook to remove.
	SetTCPPacketHook(ip netip.Addr, dPort uint16, hook func(packet []byte) bool)
}

// PacketCapture captures raw packets for debugging. Implementations must be
// safe for concurrent use and must not block.
type PacketCapture interface {
	// Offer submits a packet for capture. outbound is true for packets
	// leaving the host (Read path), false for packets arriving (Write path).
	Offer(data []byte, outbound bool)
}

// FilteredDevice to override Read or Write of packets
type FilteredDevice struct {
	tun.Device

	filter    PacketFilter
	capture   atomic.Pointer[PacketCapture]
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

	if filter != nil {
		for i := 0; i < n; i++ {
			if filter.FilterOutbound(bufs[i][offset:offset+sizes[i]], sizes[i]) {
				bufs = append(bufs[:i], bufs[i+1:]...)
				sizes = append(sizes[:i], sizes[i+1:]...)
				n--
				i--
			}
		}
	}

	if pc := d.capture.Load(); pc != nil {
		for i := 0; i < n; i++ {
			(*pc).Offer(bufs[i][offset:offset+sizes[i]], true)
		}
	}

	return n, nil
}

// Write wraps write method with filtering feature
func (d *FilteredDevice) Write(bufs [][]byte, offset int) (int, error) {
	// Capture before filtering so dropped packets are still visible in captures.
	if pc := d.capture.Load(); pc != nil {
		for _, buf := range bufs {
			(*pc).Offer(buf[offset:], false)
		}
	}

	d.mutex.RLock()
	filter := d.filter
	d.mutex.RUnlock()

	if filter == nil {
		return d.Device.Write(bufs, offset)
	}

	filteredBufs := make([][]byte, 0, len(bufs))
	dropped := 0
	for _, buf := range bufs {
		if filter.FilterInbound(buf[offset:], len(buf)) {
			dropped++
		} else {
			filteredBufs = append(filteredBufs, buf)
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

// SetCapture sets or clears the packet capture sink. Pass nil to disable.
// Uses atomic store so the hot path (Read/Write) is a single pointer load
// with no locking overhead when capture is off.
func (d *FilteredDevice) SetCapture(pc PacketCapture) {
	if pc == nil {
		d.capture.Store(nil)
		return
	}
	d.capture.Store(&pc)
}
