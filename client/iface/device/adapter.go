package device

import "golang.zx2c4.com/wireguard/tun"

// TunAdapter is an interface for create tun device from external service
type TunAdapter interface {
	ConfigureInterface(address string, addressV6 string, mtu int, dns string, searchDomains string, routes string) (int, error)
	UpdateAddr(address string) error
	ProtectSocket(fd int32) bool
}

// TunDeviceProvider is an optional interface a [TunAdapter] may also implement to supply the
// tun.Device itself, instead of a file descriptor for NetBird to open.
//
// ConfigureInterface returns a descriptor, which NetBird passes to
// tun.CreateUnmonitoredTUNFromFD; that call ioctls TUNGETIFF for the interface name, so it accepts
// only a real tun. A host that already owns the tun therefore cannot use it — and on Android a host
// may have no choice, because the platform permits exactly one active VpnService per user profile.
// An app running NetBird alongside another backend must own that single tun and route packets to
// whichever backend claims each destination; it has no second tun to hand over, and handing over
// the shared one would give NetBird every other backend's traffic.
//
// A TunAdapter that implements this is asked for a device and never for a descriptor. One that does
// not is unaffected: the descriptor path is unchanged, and gomobile bindings — which cannot express
// a Go interface return — simply do not implement this.
type TunDeviceProvider interface {
	// TunDevice returns the device NetBird should read and write, given the same interface
	// parameters ConfigureInterface receives, and the name to report for it.
	TunDevice(address string, addressV6 string, mtu int, dns string, searchDomains string, routes string) (tun.Device, string, error)
}
