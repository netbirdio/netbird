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

	// updates carries route snapshots to the single delivery goroutine. A
	// dedicated worker (rather than a fresh goroutine per notify) guarantees
	// the listener observes updates in the exact order they were produced.
	//
	// Without this ordering guarantee a stale snapshot can be delivered last
	// and clobber the correct one. On exit-node disable the ::/0 removal
	// arrives as a separate prefix update right after the 0.0.0.0/0 removal;
	// with a goroutine-per-notify the two could be reordered, leaving the
	// synthesized ::/0 default route installed on the tunnel and black-holing
	// all IPv6 traffic while IPv4 worked.
	updates chan string
}

func NewNotifier() *Notifier {
	n := &Notifier{
		// Buffered so producers (route updates run under the route manager
		// lock) don't block on the listener callback. A small buffer absorbs
		// the bursts seen during exit-node toggles.
		updates: make(chan string, 16),
	}
	go n.deliverLoop()
	return n
}

// deliverLoop is the single consumer of n.updates. Serializing delivery here
// is what preserves ordering: snapshots reach the listener one at a time, in
// production order.
func (n *Notifier) deliverLoop() {
	for routes := range n.updates {
		n.mu.Lock()
		l := n.listener
		n.mu.Unlock()
		if l != nil {
			l.OnNetworkChanged(routes)
		}
	}
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
	if slices.Equal(n.currentPrefixes, newNets) {
		n.mu.Unlock()
		return
	}
	n.currentPrefixes = newNets
	// Snapshot the delivered string under the lock so it is consistent and
	// can't race with the next update mutating currentPrefixes.
	routes := strings.Join(n.currentPrefixes, ",")
	n.mu.Unlock()

	n.updates <- routes
}

func (n *Notifier) GetInitialRouteRanges() []string {
	return nil
}
