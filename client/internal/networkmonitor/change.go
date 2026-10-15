package networkmonitor

import "github.com/netbirdio/netbird/client/internal/routemanager/systemops"

// ChangeKind classifies how the underlay default route moved.
type ChangeKind int

const (
	// ChangeNone means the default next hops are the same as before, as after
	// a route flap or a wake-up on the same network.
	ChangeNone ChangeKind = iota
	// ChangeGateway means the default route stayed on the same interface but
	// its gateway changed, as when the same Wi-Fi adapter joins another network.
	ChangeGateway
	// ChangeInterface means the default route moved to another interface,
	// even through the same gateway, as when a cable or a dock is plugged in.
	ChangeInterface
)

// NextHops holds the underlay default next hop of each address family.
type NextHops struct {
	V4 systemops.Nexthop
	V6 systemops.Nexthop
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
	case ChangeGateway:
		return "gateway"
	case ChangeInterface:
		return "interface"
	default:
		return "unknown"
	}
}

// classify reports the strongest change across both address families.
func classify(before, after NextHops) ChangeKind {
	return max(classifyFamily(before.V4, after.V4), classifyFamily(before.V6, after.V6))
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
