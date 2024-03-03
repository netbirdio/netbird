package internal

import (
	"time"

	"github.com/netbirdio/netbird/client/internal/peer"
)

type SessionWatcher struct {
	peerStatusRecorder *peer.Status
	watchTicker        *time.Ticker
	onExpireListener   func()
}

// NewSessionWatcher creates a new instance of SessionWatcher.
func NewSessionWatcher(peerStatusRecorder *peer.Status) *SessionWatcher {
	s := &SessionWatcher{
		peerStatusRecorder: peerStatusRecorder,
		watchTicker:        time.NewTicker(10 * time.Second),
	}
	go s.startWatcher()
	return s
}

// SetOnExpireListener sets the callback func to be called when the session expires.
func (s *SessionWatcher) SetOnExpireListener(onExpire func()) {
	s.onExpireListener = onExpire
}

// startWatcher starts the session watcher.
// It checks if login is required,
// if login is required and onExpireListener is set, it calls the onExpireListener.
func (s *SessionWatcher) startWatcher() {
	isLoginRequired := s.peerStatusRecorder.IsLoginRequired()
	if isLoginRequired && s.onExpireListener != nil {
		s.onExpireListener()
	}

	for {
		select {
		case <-s.watchTicker.C:
			isLoginRequired := s.peerStatusRecorder.IsLoginRequired()
			if isLoginRequired && s.onExpireListener != nil {
				s.onExpireListener()
			}
		}
	}
}

// StopWatch stops the watch ticker of the SessionWatcher,
// effectively stopping the session watching a process.
func (s *SessionWatcher) StopWatch() { s.watchTicker.Stop() }
