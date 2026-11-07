//go:build darwin && !ios

package systemops

import (
	"fmt"
	"net"
	"net/netip"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
)

// GetUnderlayNextHop returns the physical network's default next hop for the
// family of unspec, read from the routing table. With an exit node NetBird
// installs 0/1 and 128/1 on its interface, so a lookup for the default
// resolves to the tunnel, while the physical default stays in the table as
// the unscoped /0. Scoped defaults, NetBird's own included, are skipped.
func GetUnderlayNextHop(unspec netip.Addr, vpnIntf string) (Nexthop, error) {
	rib, err := retryFetchRIB()
	if err != nil {
		return Nexthop{}, fmt.Errorf("fetch routing table: %w", err)
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return Nexthop{}, fmt.Errorf("parse routing table: %w", err)
	}
	return underlayDefault(msgs, unspec, vpnIntf, net.InterfaceByIndex)
}

// underlayDefault picks the unscoped default of unspec's family that does not
// leave through vpnIntf. The interface comes from the message index: the
// parsed route only names one for an on-link gateway, not for a default
// through a router.
func underlayDefault(msgs []route.Message, unspec netip.Addr, vpnIntf string, ifaceByIndex func(int) (*net.Interface, error)) (Nexthop, error) {
	for _, msg := range msgs {
		rtMsg, ok := msg.(*route.RouteMessage)
		if !ok || rtMsg.Flags&unix.RTF_UP == 0 || rtMsg.Flags&unix.RTF_IFSCOPE != 0 {
			continue
		}
		info, err := MsgToRoute(rtMsg)
		if err != nil {
			log.Tracef("skip route message: %v", err)
			continue
		}
		if !info.Dst.IsValid() || info.Dst.Bits() != 0 || info.Dst.Addr().Is4() != unspec.Is4() {
			continue
		}
		intf, err := ifaceByIndex(rtMsg.Index)
		if err != nil {
			log.Tracef("skip route on interface %d: %v", rtMsg.Index, err)
			continue
		}
		if intf.Name == vpnIntf {
			continue
		}
		return Nexthop{IP: info.Gw, Intf: intf}, nil
	}
	return Nexthop{}, vars.ErrRouteNotFound
}
