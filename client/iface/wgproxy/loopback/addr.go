//go:build linux && !android

package loopback

import (
	"fmt"
	"net/netip"
)

// Peer endpoints live in the upper half of 127.0.0.0/8. Everything in that
// range is delivered to the loopback device without any address or route being
// configured, and staying out of 127.0.0.0/9 keeps well-known squatters such as
// 127.0.0.53 (systemd-resolved) and 127.0.1.1 out of the way.
const (
	addrRangeBase   uint32 = 0x7f800000 // 127.128.0.0
	addrRangeSize   uint32 = 1 << 23    // /9
	addrRangePrefix        = "127.128.0.0/9"
)

// allocator hands out one loopback address per relayed connection. The address
// is the peer's identity: WireGuard sends to it, and the proxy recovers which
// peer a packet belongs to from the destination address.
type allocator struct {
	cursor uint32
}

// next returns the first free address at or after the cursor, wrapping once.
// inUse reports whether an address is already handed out.
func (a *allocator) next(inUse func(netip.Addr) bool) (netip.Addr, error) {
	for i := uint32(0); i < addrRangeSize; i++ {
		a.cursor = (a.cursor + 1) % addrRangeSize
		addr := addrFromOffset(a.cursor)
		if !addr.IsValid() {
			continue
		}
		if inUse(addr) {
			continue
		}
		return addr, nil
	}
	return netip.Addr{}, fmt.Errorf("no free endpoint address in %s", addrRangePrefix)
}

// addrFromOffset maps an offset in the range to an address, skipping the .0 and
// .255 hosts. They are unremarkable on loopback, but tools and firewall rules
// tend to treat them as network and broadcast addresses.
func addrFromOffset(offset uint32) netip.Addr {
	last := offset & 0xff
	if last == 0 || last == 0xff {
		return netip.Addr{}
	}

	v := addrRangeBase + offset
	return netip.AddrFrom4([4]byte{
		byte(v >> 24),
		byte(v >> 16),
		byte(v >> 8),
		byte(v),
	})
}

// inRange reports whether addr is one this proxy could have handed out.
func inRange(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	b := addr.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return v >= addrRangeBase && v < addrRangeBase+addrRangeSize
}
