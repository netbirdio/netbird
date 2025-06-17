package common

import (
	"time"

	"github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/internal/dns"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/peerstore"
	"github.com/netbirdio/netbird/client/internal/routemanager/fakeip"
	"github.com/netbirdio/netbird/client/internal/routemanager/iface"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/route"
)

type HandlerParams struct {
	Route                *route.Route
	RouteRefCounter      *refcounter.RouteRefCounter
	AllowedIPsRefCounter *refcounter.AllowedIPsRefCounter
	DnsRouterInterval    time.Duration
	StatusRecorder       *peer.Status
	WgInterface          iface.WGIface
	DnsServer            dns.Server
	PeerStore            *peerstore.Store
	UseNewDNSRoute       bool
	Firewall             manager.Manager
	FakeIPManager        *fakeip.Manager
}
