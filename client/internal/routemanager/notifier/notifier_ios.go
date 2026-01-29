//go:build ios || tvos

package notifier

import (
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/route"
)

type Notifier struct {
	currentPrefixes []string

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

func (n *Notifier) SetInitialClientRoutes([]*route.Route, []*route.Route) {
	// iOS doesn't care about initial routes
}

func (n *Notifier) OnNewRoutes(route.HAMap) {
	// Not used on iOS
}

func (n *Notifier) OnNewPrefixes(prefixes []netip.Prefix) {
	newNets := make([]string, 0)
	for _, prefix := range prefixes {
		newNets = append(newNets, prefix.String())
	}

	sort.Strings(newNets)

	if slices.Equal(n.currentPrefixes, newNets) {
		return
	}

	n.currentPrefixes = newNets
	n.notify()
}

func (n *Notifier) notify() {
	n.listenerMux.Lock()
	defer n.listenerMux.Unlock()
	if n.listener == nil {
		return
	}

	go func(l listener.NetworkChangeListener) {
		l.OnNetworkChanged(strings.Join(n.addIPv6RangeIfNeeded(n.currentPrefixes), ","))
	}(n.listener)
}

func (n *Notifier) GetInitialRouteRanges() []string {
	return nil
}

func (n *Notifier) addIPv6RangeIfNeeded(inputRanges []string) []string {
	for _, r := range inputRanges {
		if r == "0.0.0.0/0" {
			return append(slices.Clone(inputRanges), "::/0")
		}
	}
	return inputRanges
}
