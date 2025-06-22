package notifier

import (
	"net/netip"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/route"
)

type Notifier struct {
	initialRouteRanges []string
	routeRanges        []string

	listener    listener.NetworkChangeListener
	listenerMux sync.Mutex
}

func NewNotifier() *Notifier {
	return &Notifier{}
}

func (n *Notifier) SetListener(listener listener.NetworkChangeListener) {
	n.listenerMux.Lock()
	defer n.listenerMux.Unlock()
	n.listener = listener
}

func (n *Notifier) SetInitialClientRoutes(clientRoutes []*route.Route) {
	nets := make([]string, 0)
	for _, r := range clientRoutes {
		if r.IsDynamic() {
			continue
		}
		nets = append(nets, r.Network.String())
	}
	sort.Strings(nets)
	n.initialRouteRanges = nets
}

func (n *Notifier) OnNewRoutes(idMap route.HAMap) {
	if runtime.GOOS != "android" {
		return
	}

	var newNets []string
	for _, routes := range idMap {
		for _, r := range routes {
			if r.IsDynamic() {
				continue
			}
			newNets = append(newNets, r.Network.String())
		}
	}

	sort.Strings(newNets)
	if !n.hasDiff(n.initialRouteRanges, newNets) {
		return
	}

	n.routeRanges = newNets
	n.notify()
}

// OnNewPrefixes is called from iOS only
func (n *Notifier) OnNewPrefixes(prefixes []netip.Prefix) {
	newNets := make([]string, 0)
	for _, prefix := range prefixes {
		newNets = append(newNets, prefix.String())
	}

	sort.Strings(newNets)
	if !n.hasDiff(n.routeRanges, newNets) {
		return
	}

	n.routeRanges = newNets
	n.notify()
}

func (n *Notifier) notify() {
	n.listenerMux.Lock()
	defer n.listenerMux.Unlock()
	if n.listener == nil {
		return
	}

	go func(l listener.NetworkChangeListener) {
		l.OnNetworkChanged(strings.Join(addIPv6RangeIfNeeded(n.routeRanges), ","))
	}(n.listener)
}

func (n *Notifier) hasDiff(a []string, b []string) bool {
	if len(a) != len(b) {
		return true
	}
	for i, v := range a {
		if v != b[i] {
			return true
		}
	}
	return false
}

func (n *Notifier) GetInitialRouteRanges() []string {
	return addIPv6RangeIfNeeded(n.initialRouteRanges)
}

// addIPv6RangeIfNeeded returns the input ranges with the default IPv6 range when there is an IPv4 default route.
func addIPv6RangeIfNeeded(inputRanges []string) []string {
	ranges := inputRanges
	for _, r := range inputRanges {
		// we are intentionally adding the ipv6 default range in case of ipv4 default range
		// to ensure that all traffic is managed by the tunnel interface on android
		if r == "0.0.0.0/0" {
			ranges = append(ranges, "::/0")
			break
		}
	}
	return ranges
}
