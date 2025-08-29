package dns

import (
	"reflect"
	"sort"
	"sync"

	"github.com/netbirdio/netbird/client/internal/listener"
)

type notifier struct {
	listener      listener.NetworkChangeListener
	listenerMux   sync.Mutex
	searchDomains []string
}

func newNotifier(initialSearchDomains []string) *notifier {
	sort.Strings(initialSearchDomains)
	return &notifier{
		searchDomains: initialSearchDomains,
	}
}

func (n *notifier) setListener(listener listener.NetworkChangeListener) {
	n.listenerMux.Lock()
	defer n.listenerMux.Unlock()
	n.listener = listener
}

func (n *notifier) onNewSearchDomains(searchDomains []string) {
	sort.Strings(searchDomains)

	if len(n.searchDomains) != len(searchDomains) {
		n.searchDomains = searchDomains
		n.notify()
		return
	}

	if reflect.DeepEqual(n.searchDomains, searchDomains) {
		return
	}

	n.searchDomains = searchDomains
	n.notify()
}

func (n *notifier) notify() {
	n.listenerMux.Lock()
	defer n.listenerMux.Unlock()
	if n.listener == nil {
		return
	}

	go func(l listener.NetworkChangeListener) {
		l.OnNetworkChanged("")
	}(n.listener)
}
