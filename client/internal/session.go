package internal

import (
	"context"
	"sync"
	"time"

	"github.com/netbirdio/netbird/client/internal/peer"
)

type SessionWatcher struct {
	ctx   context.Context
	mutex sync.Mutex

	peerStatusRecorder *peer.Status
	watchTicker        *time.Ticker

	onExpireListener func()
}

// NewSessionWatcher creates a new instance of SessionWatcher.
func NewSessionWatcher(ctx context.Context, peerStatusRecorder *peer.Status) *SessionWatcher {
	s := &SessionWatcher{
		ctx:                ctx,
		peerStatusRecorder: peerStatusRecorder,
		watchTicker:        time.NewTicker(10 * time.Second),
	}
	go s.startWatcher()
	return s
}

// SetOnExpireListener sets the callback func to be called when the session expires.
func (s *SessionWatcher) SetOnExpireListener(onExpire func()) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.onExpireListener = onExpire
}

// startWatcher continuously checks if the session requires login and
// calls the onExpireListener if login is required.
func (s *SessionWatcher) startWatcher() {
	isLoginRequired := s.peerStatusRecorder.IsLoginRequired()
	if isLoginRequired && s.onExpireListener != nil {
		s.onExpireListener()
	}

	for {
		select {
		case <-s.ctx.Done():
			s.watchTicker.Stop()
			return
		case <-s.watchTicker.C:
			isLoginRequired := s.peerStatusRecorder.IsLoginRequired()
			if isLoginRequired && s.onExpireListener != nil {
				s.mutex.Lock()
				s.onExpireListener()
				s.mutex.Unlock()
			}
		}
	}
}
