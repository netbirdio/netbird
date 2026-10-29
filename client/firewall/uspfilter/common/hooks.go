package common

import (
	"net/netip"
	"sync/atomic"
)

// PacketHook stores a registered hook for a specific IP:port.
type PacketHook struct {
	IP   netip.Addr
	Port uint16
	Fn   func([]byte) bool
}

// HookMatches checks if a packet's destination matches the hook and invokes it.
func HookMatches(h *PacketHook, dstIP netip.Addr, dport uint16, packetData []byte) bool {
	if h == nil {
		return false
	}
	if h.IP == dstIP && h.Port == dport {
		return h.Fn(packetData)
	}
	return false
}

// SetHook atomically stores a hook, handling nil removal.
func SetHook(ptr *atomic.Pointer[PacketHook], ip netip.Addr, dPort uint16, hook func([]byte) bool) {
	if hook == nil {
		ptr.Store(nil)
		return
	}
	ptr.Store(&PacketHook{
		IP:   ip,
		Port: dPort,
		Fn:   hook,
	})
}
