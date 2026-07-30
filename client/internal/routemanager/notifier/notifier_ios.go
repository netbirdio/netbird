//go:build ios

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
	mu              sync.Mutex
	currentPrefixes []string
	listener        listener.NetworkChangeListener
}

func NewNotifier() *Notifier {
	return &Notifier{}
}

func (n *Notifier) SetListener(listener listener.NetworkChangeListener) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.listener = listener
}

func (n *Notifier) SetInitialClientRoutes([]*route.Route, []*route.Route) {
	// iOS doesn't care about initial routes
}

func (n *Notifier) SetFakeIPRoutes([]*route.Route) {
	// Not used on iOS
}

func (n *Notifier) OnNewRoutes(route.HAMap) {
	// Not used on iOS
}

func (n *Notifier) OnNewPrefixes(prefixes []netip.Prefix) {
	newNets := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		newNets = append(newNets, prefix.String())
	}

	sort.Strings(newNets)

	n.mu.Lock()
	defer n.mu.Unlock()
	if slices.Equal(n.currentPrefixes, newNets) {
		return
	}
	n.currentPrefixes = newNets
	if n.listener != nil {
		n.listener.OnNetworkChanged(strings.Join(n.currentPrefixes, ","))
	}
}

func (n *Notifier) Close() {
}

func (n *Notifier) GetInitialRouteRanges() []string {
	return nil
}
