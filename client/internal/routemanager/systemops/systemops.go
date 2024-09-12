package systemops

import (
	"net"
	"net/netip"
	"sync"

	"github.com/netbirdio/netbird/client/internal/routemanager/notifier"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/iface"
)

type Nexthop struct {
	IP   netip.Addr
	Intf *net.Interface
}

type ExclusionCounter = refcounter.Counter[any, Nexthop]

type SysOps struct {
	refCounter  *ExclusionCounter
	wgInterface iface.IWGIface
	// prefixes is tracking all the current added prefixes im memory
	// (this is used in iOS as all route updates require a full table update)
	//nolint
	prefixes map[netip.Prefix]struct{}
	//nolint
	mu sync.Mutex
	// notifier is used to notify the system of route changes (also used on mobile)
	notifier *notifier.Notifier
}

func NewSysOps(wgInterface iface.IWGIface, notifier *notifier.Notifier) *SysOps {
	return &SysOps{
		wgInterface: wgInterface,
		notifier:    notifier,
	}
}
