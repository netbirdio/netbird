package internal

import (
	"context"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/netbirdio/netbird/client/internal/peer"
)

type SessionWatcher struct {
	ctx   context.Context
	mutex sync.Mutex

	peerStatusRecorder *peer.Status
	watchTicker        *time.Ticker

	sendNotification bool
	onExpireListener func()
}

// NewSessionWatcher creates a new instance of SessionWatcher.
func NewSessionWatcher(ctx context.Context, peerStatusRecorder *peer.Status) *SessionWatcher {
	s := &SessionWatcher{
		ctx:                ctx,
		peerStatusRecorder: peerStatusRecorder,
		watchTicker:        time.NewTicker(2 * time.Second),
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
	for {
		select {
		case <-s.ctx.Done():
			s.watchTicker.Stop()
			return
		case <-s.watchTicker.C:
			managementState := s.peerStatusRecorder.GetManagementState()
			if managementState.Connected {
				s.sendNotification = true
			}

			isLoginRequired := s.peerStatusRecorder.IsLoginRequired()
			if isLoginRequired && s.sendNotification && s.onExpireListener != nil {
				s.mutex.Lock()
				s.onExpireListener()
				s.sendNotification = false
				s.mutex.Unlock()
			}
		}
	}
}

// CheckUIApp checks whether UI application is running.
func CheckUIApp() bool {
	cmd := exec.Command("ps", "-ef")
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "netbird-ui") && !strings.Contains(line, "grep") {
			return true
		}
	}
	return false
}
