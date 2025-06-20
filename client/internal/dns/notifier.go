package dns

import (
	"sync"

	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/management/domain"
)

type notifier struct {
	listener      listener.NetworkChangeListener
	listenerMux   sync.Mutex
	searchDomains domain.List
}

func newNotifier(initialSearchDomains domain.List) *notifier {
	return &notifier{
		searchDomains: initialSearchDomains,
	}
}

func (n *notifier) setListener(listener listener.NetworkChangeListener) {
	n.listenerMux.Lock()
	defer n.listenerMux.Unlock()
	n.listener = listener
}

func (n *notifier) onNewSearchDomains(searchDomains domain.List) {
	if searchDomains.Equal(n.searchDomains) {
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
