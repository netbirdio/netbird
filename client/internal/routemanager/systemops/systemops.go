package systemops

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/routemanager/notifier"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
)

type Nexthop struct {
	IP   netip.Addr
	Intf *net.Interface
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
}

func NewSysOps(wgInterface wgIface, notifier *notifier.Notifier) *SysOps {
	return &SysOps{
		wgInterface: wgInterface,
		notifier:    notifier,
	}
}

//nolint:unused // only used on BSD systems
func (r *SysOps) getSeq() int {
	return int(r.seq.Add(1))
}

func (r *SysOps) validateRoute(prefix netip.Prefix) error {
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
