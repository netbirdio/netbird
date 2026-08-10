// Package netstate tracks OS-reported network availability for the client.
//
// A State instance is owned by the platform integration (e.g. the Android or
// iOS bindings, fed from ConnectivityManager callbacks or NWPathMonitor) and
// is injected into the connection retry loops (management, signal, relay,
// peer guards and the top-level connect loop), which consult it to avoid
// burning CPU and battery on reconnect attempts while the device has no
// network at all (e.g. airplane mode), and to reset their backoff as soon as
// the network returns.
//
// Consumers hold a *State that may be nil — every non-mobile platform leaves
// it unset. The read methods are safe on a nil receiver: they report online
// and never block, so consumers behave as if this package did not exist.
package netstate

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"
)

// State holds the OS-reported network availability. The zero value is not
// usable; create instances with New.
type State struct {
	mu      sync.Mutex
	online  bool
	changed chan struct{}
}

// New creates a State that starts online.
func New() *State {
	return &State{
		online:  true,
		changed: make(chan struct{}),
	}
}

// Set records whether the OS reports any usable network. Transitions wake up
// all Wait callers immediately.
func (s *State) Set(online bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.online == online {
		return
	}
	s.online = online
	close(s.changed)
	s.changed = make(chan struct{})
	log.Infof("OS network availability changed: online=%t", online)
}

// IsOnline reports whether the OS reports at least one usable network. On a
// nil receiver — no State injected — it reports online.
func (s *State) IsOnline() bool {
	if s == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.online
}

// Wait blocks while the network is offline. It reports whether it had to
// wait, so callers can reset their backoff after an outage. It returns early
// with the context error when ctx is done. On a nil receiver — no State
// injected — it returns immediately.
func (s *State) Wait(ctx context.Context) (bool, error) {
	if s == nil {
		return false, nil
	}
	waited := false
	for {
		s.mu.Lock()
		if s.online {
			s.mu.Unlock()
			return waited, nil
		}
		ch := s.changed
		s.mu.Unlock()

		if !waited {
			waited = true
			log.Debugf("network is offline, pausing connection attempts")
		}

		select {
		case <-ctx.Done():
			return waited, ctx.Err()
		case <-ch:
		}
	}
}
