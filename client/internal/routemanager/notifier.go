package routemanager

import (
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/route"
)

type notifier struct {
	initialRouteRanges []string
	routeRanges        []string

	listener    listener.NetworkChangeListener
	listenerMux sync.Mutex
}

func newNotifier() *notifier {
	return &notifier{}
}

func (n *notifier) setListener(listener listener.NetworkChangeListener) {
	n.listenerMux.Lock()
	defer n.listenerMux.Unlock()
	n.listener = listener
}

func (n *notifier) setInitialClientRoutes(clientRoutes []*route.Route) {
	nets := make([]string, 0)
	for _, r := range clientRoutes {
		nets = append(nets, r.Network.String())
	}
	sort.Strings(nets)
	n.initialRouteRanges = nets
}

func (n *notifier) onNewRoutes(idMap route.HAMap) {
	newNets := make([]string, 0)
	for _, routes := range idMap {
		for _, r := range routes {
			newNets = append(newNets, r.Network.String())
		}
	}

	sort.Strings(newNets)
	switch runtime.GOOS {
	case "android":
		if !n.hasDiff(n.initialRouteRanges, newNets) {
			return
		}
	default:
		if !n.hasDiff(n.routeRanges, newNets) {
			return
		}
	}

	n.routeRanges = newNets

	n.notify()
}

func (n *notifier) notify() {
	n.listenerMux.Lock()
	defer n.listenerMux.Unlock()
	if n.listener == nil {
		return
	}

	go func(l listener.NetworkChangeListener) {
		l.OnNetworkChanged(strings.Join(addIPv6RangeIfNeeded(n.routeRanges), ","))
	}(n.listener)
}

func (n *notifier) hasDiff(a []string, b []string) bool {
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

func (n *notifier) getInitialRouteRanges() []string {
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
