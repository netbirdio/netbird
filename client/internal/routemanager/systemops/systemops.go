package systemops

import (
	"net"
	"net/netip"

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
	wgInterface *iface.WGIface
}

func NewSysOps(wgInterface *iface.WGIface) *SysOps {
	return &SysOps{
		wgInterface: wgInterface,
	}
}
