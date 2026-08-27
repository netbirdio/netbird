package internal

import (
	"context"
	"sync"

	log "github.com/sirupsen/logrus"
)

// RunSupervisor tracks which run of a logical connection is current.
//
// A ConnectClient is single-use, so every attempt builds a fresh one. Without a
// record of which attempt is current, a stale one can publish its client over a
// newer one's, and a teardown can target a client that has already been
// replaced — leaving the live one running with nothing tracking it.
//
// A run claims a generation with Begin, publishes its client with Publish, and
// closes the channel Begin returned when it exits. Publish refuses a client from
// a run that is no longer current and stops the client it displaces, so no
// ConnectClient is dropped without being stopped.
//
// The zero value is ready to use.
type RunSupervisor struct {
	mu         sync.Mutex
	generation uint64
	current    *ConnectClient
	done       chan struct{}
}

// Begin claims a generation for a starting run. The caller must close the
// returned channel when the run exits, whether or not it published a client.
func (s *RunSupervisor) Begin() (uint64, chan struct{}) {
	done := make(chan struct{})

	s.mu.Lock()
	defer s.mu.Unlock()

	s.generation++
	s.done = done

	return s.generation, done
}

// Publish installs cc as the current client and reports whether it took effect.
// It returns false once a newer Begin or a Stop has superseded the generation,
// and the caller must then abandon its startup. A client it displaces within the
// same run is stopped, with stopCtx bounding that wait.
func (s *RunSupervisor) Publish(ctx context.Context, generation uint64, cc *ConnectClient) bool {
	s.mu.Lock()
	if s.generation != generation {
		s.mu.Unlock()
		return false
	}
	displaced := s.current
	s.current = cc
	s.mu.Unlock()

	if displaced != nil && displaced != cc {
		if err := displaced.StopWithContext(ctx); err != nil {
			log.Warnf("stopping the displaced connect client: %v", err)
		}
	}

	return true
}

// Current returns the published client, or nil while no run has published one.
func (s *RunSupervisor) Current() *ConnectClient {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.current
}

// Done returns the channel the most recent run closes when it exits, or nil
// when no run has been started. It stays readable after Stop so a waiter that
// raced a teardown still observes the run's exit instead of a nil channel.
// Callers that only need a yes/no answer should use Alive.
func (s *RunSupervisor) Done() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.done
}

// Alive reports whether a run has claimed a generation and not yet signalled its
// exit.
func (s *RunSupervisor) Alive() bool {
	s.mu.Lock()
	done := s.done
	s.mu.Unlock()

	if done == nil {
		return false
	}

	select {
	case <-done:
		return false
	default:
		return true
	}
}

// Stop invalidates any run in flight, stops the published client, and waits for
// the run to signal its exit. It gives up the wait when ctx is done and returns
// ctx.Err(); the run stays cancelled and finishes tearing down in the
// background, so an early return does not mean the engine is gone.
func (s *RunSupervisor) Stop(ctx context.Context) error {
	s.mu.Lock()
	s.generation++
	cc := s.current
	done := s.done
	s.current = nil
	s.mu.Unlock()

	if cc != nil {
		if err := cc.StopWithContext(ctx); err != nil {
			return err
		}
	}

	if done == nil {
		return nil
	}

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
