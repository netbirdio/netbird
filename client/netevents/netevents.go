// Package netevents owns the OS network event handling shared by the mobile
// bindings: availability changes park or wake the reconnection loops and drive
// the NoNetwork listener state, and both losing the last network and switching
// networks sweep the stale connections so their owners redial immediately.
package netevents

import (
	"context"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/netevents/netstate"
	"github.com/netbirdio/netbird/client/netevents/sweep"
)

// Recorder receives the availability changes for listener state reporting.
type Recorder interface {
	SetNetworkAvailable(available bool)
}

// Manager ties the network availability state, the connection sweeper and the
// status recorder together; it outlives engine restarts. A nil *Manager is
// the valid no-events value: the read methods report always-online and never
// sweep.
type Manager struct {
	netState *netstate.State
	sweeper  *sweep.Sweeper
	recorder Recorder
}

// NewManager creates a Manager reporting into recorder, starting online.
func NewManager(recorder Recorder) *Manager {
	return &Manager{
		netState: netstate.New(),
		sweeper:  sweep.New(),
		recorder: recorder,
	}
}

// SetNetworkAvailable records OS-reported network availability. While
// unavailable, the reconnection loops suspend their attempts and the
// connection listener reports NoNetwork instead of Connecting; when
// availability returns, the loops resume immediately with a fresh backoff.
// Losing the last network also sweeps the registered connections: nothing can
// redial while offline, so the stale sockets would otherwise stay silently
// "connected" until their own timeouts and the client would keep reporting
// Connected with no network at all.
func (m *Manager) SetNetworkAvailable(available bool) {
	if !available && m.netState.IsOnline() {
		m.sweeper.MarkNetworkChange()
	}
	m.netState.Set(available)
	m.recorder.SetNetworkAvailable(available)
}

// NotifyNetworkChange marks the management, signal and relay connections
// stale after the OS switched networks and schedules a sweep that cuts
// whatever has not redialed on the new network by then. The engine and the
// TUN device stay untouched.
func (m *Manager) NotifyNetworkChange() {
	m.sweeper.MarkNetworkChange()
	log.Infof("network change: connections marked stale")
}

// IsOnline reports whether the OS reports at least one usable network.
func (m *Manager) IsOnline() bool {
	if m == nil {
		return true
	}
	return m.netState.IsOnline()
}

// Changed returns a channel closed on the next availability transition.
func (m *Manager) Changed() <-chan struct{} {
	if m == nil {
		return nil
	}
	return m.netState.Changed()
}

// Wait blocks while the network is offline; see netstate.State.Wait.
func (m *Manager) Wait(ctx context.Context) (bool, error) {
	if m == nil {
		return false, nil
	}
	return m.netState.Wait(ctx)
}

// WaitSettled waits until an online verdict holds for a full settleWindow, or
// while offline until the budget runs out. Returns false when ctx is
// cancelled. The settle window exists because a disconnect often precedes the
// OS offline flag by a few milliseconds, so a fresh online verdict cannot be
// trusted immediately. A nil Manager has no events to watch: it degrades to a
// fixed budget-long sleep.
func (m *Manager) WaitSettled(ctx context.Context, budget, settleWindow time.Duration) bool {
	if m == nil {
		select {
		case <-time.After(budget):
			return true
		case <-ctx.Done():
			return false
		}
	}

	budgetTimer := time.NewTimer(budget)
	defer budgetTimer.Stop()

	settle := time.NewTimer(settleWindow)
	defer settle.Stop()

	for {
		// Channel first, flag second: a flip in between still fires the channel.
		changedCh := m.netState.Changed()
		if m.netState.IsOnline() {
			select {
			case <-settle.C:
				return true
			case <-changedCh:
			case <-ctx.Done():
				return false
			}
		} else {
			select {
			case <-budgetTimer.C:
				return true
			case <-changedCh:
			case <-ctx.Done():
				return false
			}
		}
		if !settle.Stop() {
			select {
			case <-settle.C:
			default:
			}
		}
		settle.Reset(settleWindow)
	}
}

// StartDial registers an in-flight dial with the sweeper; see sweep.Sweeper.StartDial.
func (m *Manager) StartDial(ctx context.Context) *sweep.Dial {
	if m == nil {
		return (*sweep.Sweeper)(nil).StartDial(ctx)
	}
	return m.sweeper.StartDial(ctx)
}

// QuickRetryBackoff wraps bo for a quick retry after a network change; see
// sweep.Sweeper.QuickRetryBackoff.
func (m *Manager) QuickRetryBackoff(ctx context.Context, bo backoff.BackOff) backoff.BackOff {
	if m == nil {
		return bo
	}
	return m.sweeper.QuickRetryBackoff(ctx, bo, m.netState)
}
