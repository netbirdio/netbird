//go:build ios

package notifier

import (
	"container/list"
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
	cond            *sync.Cond
	currentPrefixes []string
	listener        listener.NetworkChangeListener
	queue           *list.List
	closed          bool
}

func NewNotifier() *Notifier {
	n := &Notifier{
		queue: list.New(),
	}
	n.cond = sync.NewCond(&n.mu)
	go n.deliverLoop()
	return n
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
	routes := strings.Join(n.currentPrefixes, ",")
	n.queue.PushBack(routes)
	n.cond.Signal()
	n.mu.Unlock()
}

func (n *Notifier) Close() {
	n.mu.Lock()
	n.closed = true
	n.cond.Signal()
	n.mu.Unlock()
}

func (n *Notifier) GetInitialRouteRanges() []string {
	return nil
}

func (n *Notifier) deliverLoop() {
	for {
		n.mu.Lock()
		for n.queue.Len() == 0 && !n.closed {
			n.cond.Wait()
		}
		if n.closed && n.queue.Len() == 0 {
			n.mu.Unlock()
			return
		}
		routes := n.queue.Remove(n.queue.Front()).(string)
		l := n.listener
		n.mu.Unlock()

		if l != nil {
			l.OnNetworkChanged(routes)
		}
	}
}
