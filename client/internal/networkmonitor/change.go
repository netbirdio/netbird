package networkmonitor

import (
	"net/netip"
	"slices"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

// ChangeKind classifies how the underlay default route moved.
type ChangeKind int

const (
	// ChangeNone means the default next hops are the same as before, as after
	// a route flap.
	ChangeNone ChangeKind = iota
	// ChangeAddress means the default interface and gateway stayed, but the
	// interface addresses changed, as with a new DHCP lease.
	ChangeAddress
	// ChangeGateway means the default route stayed on the same interface but
	// its gateway changed, as when the same Wi-Fi adapter joins another network.
	ChangeGateway
	// ChangeInterface means the default route moved to another interface,
	// even through the same gateway, as when a cable or a dock is plugged in.
	ChangeInterface
	// ChangeWake means the system woke up from sleep during the change,
	// whatever the routes did. Wake-ups keep today's restart.
	ChangeWake
)

// NextHops is the underlay snapshot: the default next hop of each address
// family and the addresses of the default interfaces.
type NextHops struct {
	V4 systemops.Nexthop
	V6 systemops.Nexthop
	// Addrs holds the unicast addresses of the default interfaces, sorted and
	// without link-local ones.
	Addrs []netip.Addr
}

// Change describes one debounced underlay change.
type Change struct {
	Kind   ChangeKind
	Before NextHops
	After  NextHops
}

// String returns the change kind as it appears in logs.
func (k ChangeKind) String() string {
	switch k {
	case ChangeNone:
		return "none"
	case ChangeAddress:
		return "address"
	case ChangeGateway:
		return "gateway"
	case ChangeInterface:
		return "interface"
	case ChangeWake:
		return "wake"
	default:
		return "unknown"
	}
}

// classify reports the strongest change across both address families. An
// address change counts only when the next hops did not move.
func classify(before, after NextHops) ChangeKind {
	kind := max(classifyFamily(before.V4, after.V4), classifyFamily(before.V6, after.V6))
	if kind == ChangeNone && !slices.Equal(before.Addrs, after.Addrs) {
		return ChangeAddress
	}
	return kind
}

func classifyFamily(before, after systemops.Nexthop) ChangeKind {
	if !sameInterface(before, after) {
		return ChangeInterface
	}
	if before.IP != after.IP {
		return ChangeGateway
	}
	return ChangeNone
}

func sameInterface(a, b systemops.Nexthop) bool {
	if a.Intf == nil || b.Intf == nil {
		return a.Intf == nil && b.Intf == nil
	}
	return a.Intf.Index == b.Intf.Index
}
