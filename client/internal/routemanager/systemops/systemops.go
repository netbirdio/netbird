package systemops

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/routemanager/notifier"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
)

type Nexthop struct {
	IP   netip.Addr
	Intf *net.Interface
}

// Route represents a basic network route with core routing information
type Route struct {
	Dst       netip.Prefix
	Gw        netip.Addr
	Interface *net.Interface
}

// DetailedRoute extends Route with additional metadata for display and debugging
type DetailedRoute struct {
	Route
	Metric          int
	InterfaceMetric int
	InterfaceIndex  int
	Protocol        string
	Scope           string
	Type            string
	Table           string
	Flags           string
}

// Equal checks if two nexthops are equal.
func (n Nexthop) Equal(other Nexthop) bool {
	return n.IP == other.IP && (n.Intf == nil && other.Intf == nil ||
		n.Intf != nil && other.Intf != nil && n.Intf.Index == other.Intf.Index)
}

// String returns a string representation of the nexthop.
func (n Nexthop) String() string {
	if n.Intf == nil {
		return n.IP.String()
	}
	if n.IP.IsValid() {
		return fmt.Sprintf("%s @ %d (%s)", n.IP.String(), n.Intf.Index, n.Intf.Name)
	}
	return fmt.Sprintf("no-ip @ %d (%s)", n.Intf.Index, n.Intf.Name)
}

type wgIface interface {
	Address() wgaddr.Address
	Name() string
}

type ExclusionCounter = refcounter.Counter[netip.Prefix, struct{}, Nexthop]

type SysOps struct {
	refCounter  *ExclusionCounter
	wgInterface wgIface
	// prefixes is tracking all the current added prefixes im memory
	// (this is used in iOS as all route updates require a full table update)
	//nolint
	prefixes map[netip.Prefix]struct{}
	//nolint
	mu sync.Mutex
	// notifier is used to notify the system of route changes (also used on mobile)
	notifier *notifier.Notifier
	// seq is an atomic counter for generating unique sequence numbers for route messages
	//nolint:unused // only used on BSD systems
	seq atomic.Uint32

	localSubnetsCache     []*net.IPNet
	localSubnetsCacheMu   sync.RWMutex
	localSubnetsCacheTime time.Time
}

func New(wgInterface wgIface, notifier *notifier.Notifier) *SysOps {
	return &SysOps{
		wgInterface: wgInterface,
		notifier:    notifier,
	}
}

//nolint:unused // only used on BSD systems
func (r *SysOps) getSeq() int {
	return int(r.seq.Add(1))
}

var t = true

func (r *SysOps) validateRoute(prefix netip.Prefix) error {
	if t {
		return nil
	}
	addr := prefix.Addr()

	switch {
	case
		!addr.IsValid(),
		addr.IsLoopback(),
		addr.IsLinkLocalUnicast(),
		addr.IsLinkLocalMulticast(),
		addr.IsInterfaceLocalMulticast(),
		addr.IsMulticast(),
		addr.IsUnspecified() && prefix.Bits() != 0,
		r.wgInterface.Address().Network.Contains(addr):
		return vars.ErrRouteNotAllowed
	}
	return nil
}
