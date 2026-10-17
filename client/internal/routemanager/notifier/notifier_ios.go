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
	batch           prefixBatch
}

func NewNotifier() *Notifier {
	return &Notifier{}
}

func (n *Notifier) SetListener(listener listener.NetworkChangeListener) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.listener = listener
}

func (n *Notifier) NotifyRouteChange() {
	// Not used on iOS
}

func (n *Notifier) OnNewRoutes(route.HAMap) {
	// Not used on iOS
}

// BeginBatch holds prefix announcements back until the matching EndBatch, which
// announces the newest set once. The route manager adds and removes system routes
// one prefix at a time, and on iOS every announcement reconfigures the tunnel.
func (n *Notifier) BeginBatch() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.batch.begin()
}

// EndBatch closes the batch opened by BeginBatch and announces the newest prefix
// set held since, if any.
func (n *Notifier) EndBatch() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if prefixes, ok := n.batch.end(); ok {
		n.announcePrefixesLocked(prefixes)
	}
}

func (n *Notifier) OnNewPrefixes(prefixes []netip.Prefix) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.batch.hold(prefixes) {
		return
	}
	n.announcePrefixesLocked(prefixes)
}

// announcePrefixesLocked hands the listener the sorted prefix set when it differs
// from the last one announced. Caller holds n.mu.
func (n *Notifier) announcePrefixesLocked(prefixes []netip.Prefix) {
	newNets := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		newNets = append(newNets, prefix.String())
	}
	sort.Strings(newNets)

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
