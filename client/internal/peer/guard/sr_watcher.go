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

	listeners     map[chan struct{}]struct{}
	mu            sync.Mutex
	iFaceDiscover stdnet.ExternalIFaceDiscover
	iceConfig     ice.Config
}

// NewSRWatcher todo: implement cancel function in thread safe way. The context cancle is dangerous because during an
// engine restart maybe we overwrite the new listeners in signal and relayManager
func NewSRWatcher(signalClient chNotifier, relayManager chNotifier, iFaceDiscover stdnet.ExternalIFaceDiscover, iceConfig ice.Config) *SRWatcher {
	srw := &SRWatcher{
		signalClient:  signalClient,
		relayManager:  relayManager,
		iFaceDiscover: iFaceDiscover,
		iceConfig:     iceConfig,
	}
	return srw
}

func (w *SRWatcher) Start(ctx context.Context) {
	iceMonitor := NewICEMonitor(w.iFaceDiscover, w.iceConfig)
	go iceMonitor.Start(ctx)
	// todo read iceMonitor.ReconnectCh

	w.signalClient.SetOnReconnectedListener(w.onReconnected)
	w.relayManager.SetOnReconnectedListener(w.onReconnected)
}

func (w *SRWatcher) onReconnected() {
	if !w.signalClient.Ready() {
		return
	}
	if w.relayManager.Ready() {
		return
	}
	w.notify()
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

func (w *SRWatcher) notify() {
	log.Infof("------ Siganl or relay reconnected!")
	w.mu.Lock()
	defer w.mu.Unlock()
	for listener := range w.listeners {
		select {
		case listener <- struct{}{}:
		}
	}
}
