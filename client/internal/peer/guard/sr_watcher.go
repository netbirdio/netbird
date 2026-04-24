package guard

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/netbirdio/netbird/client/internal/stdnet"
)

type chNotifier interface {
	SetOnReconnectedListener(func())
	Ready() bool
}

type SRWatcher struct {
	signalClient chNotifier
	relayManager chNotifier

	listeners        map[chan struct{}]struct{}
	mu               sync.Mutex
	iFaceDiscover    stdnet.ExternalIFaceDiscover
	iceConfig        ice.Config
	cancelIceMonitor context.CancelFunc
}

// NewSRWatcher creates a new SRWatcher. This watcher will notify the listeners when the ICE candidates change or the
// Relay connection is reconnected or the Signal client reconnected.
func NewSRWatcher(signalClient chNotifier, relayManager chNotifier, iFaceDiscover stdnet.ExternalIFaceDiscover, iceConfig ice.Config) *SRWatcher {
	srw := &SRWatcher{
		signalClient:  signalClient,
		relayManager:  relayManager,
		iFaceDiscover: iFaceDiscover,
		iceConfig:     iceConfig,
		listeners:     make(map[chan struct{}]struct{}),
	}
	return srw
}

func (w *SRWatcher) Start() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.cancelIceMonitor != nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	w.cancelIceMonitor = cancel

	iceMonitor := NewICEMonitor(w.iFaceDiscover, w.iceConfig, GetICEMonitorPeriod())
	go iceMonitor.Start(ctx, w.onICEChanged)
	w.signalClient.SetOnReconnectedListener(w.onReconnected)
	w.relayManager.SetOnReconnectedListener(w.onReconnected)

}

func (w *SRWatcher) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.cancelIceMonitor == nil {
		return
	}
	w.cancelIceMonitor()
	w.signalClient.SetOnReconnectedListener(nil)
	w.relayManager.SetOnReconnectedListener(nil)
}

func (w *SRWatcher) NewListener() chan struct{} {
	w.mu.Lock()
	defer w.mu.Unlock()

	listenerChan := make(chan struct{}, 1)
	w.listeners[listenerChan] = struct{}{}
	return listenerChan
}

func (w *SRWatcher) RemoveListener(listenerChan chan struct{}) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.listeners, listenerChan)
	close(listenerChan)
}

func (w *SRWatcher) onICEChanged() {
	if !w.signalClient.Ready() {
		return
	}

	log.Infof("network changes detected by ICE agent")
	w.notify()
}

func (w *SRWatcher) onReconnected() {
	if !w.signalClient.Ready() {
		return
	}
	if !w.relayManager.Ready() {
		return
	}

	log.Infof("reconnected to Signal or Relay server")
	w.notify()
}

func (w *SRWatcher) notify() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for listener := range w.listeners {
		select {
		case listener <- struct{}{}:
		default:
		}
	}
}
