package internal

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// mapStateManager is the single read/write point between the management stream
// (writes) and the convergence loop (reads/applies).
//
// The stream calls SetTarget with the latest full SyncResponse — the complete
// desired state. A single background goroutine (run) applies it to the engine in
// bounded passes via apply() until converged, releasing syncMsgMux between passes
// so other subsystems interleave. If a newer update arrives mid-flight, the loop
// keeps converging toward the latest target.
//
// State is a single comparison: appliedGen == targetGen means converged.
// targetGen increments on every SetTarget (an internal generation counter, so it
// also covers config-only updates that carry no network-map serial).
type mapStateManager struct {
	// apply performs one bounded apply pass and reports whether more passes are needed.
	apply func(*mgmProto.SyncResponse) (bool, error)
	// onConverged is called once per target when it is fully applied, with the
	// elapsed time since that target was set (for the sync-duration metric).
	onConverged func(time.Duration)

	mu          sync.Mutex
	target      *mgmProto.SyncResponse
	targetGen   uint64
	appliedGen  uint64
	targetSetAt time.Time

	wake chan struct{}
}

func newMapStateManager(apply func(*mgmProto.SyncResponse) (bool, error), onConverged func(time.Duration)) *mapStateManager {
	return &mapStateManager{
		apply:       apply,
		onConverged: onConverged,
		wake:        make(chan struct{}, 1),
	}
}

// SetTarget records the latest update as the desired state and wakes the loop.
// It returns immediately; convergence happens in the background. Serial-based
// staleness of the network map is still enforced inside apply (updateNetworkMap).
func (m *mapStateManager) SetTarget(update *mgmProto.SyncResponse) error {
	m.mu.Lock()
	m.target = update
	// Bump an internal generation counter, NOT the map serial: config-only updates
	// (relay token rotation, STUN/TURN) arrive with NetworkMap == nil and carry no
	// serial, yet must still be applied. Every SetTarget is therefore a distinct
	// target regardless of payload. Map-serial staleness is enforced separately
	// inside apply (updateNetworkMap).
	m.targetGen++
	m.targetSetAt = time.Now()
	m.mu.Unlock()

	select {
	case m.wake <- struct{}{}:
	default:
	}
	return nil
}

// run drives convergence until ctx is done. It is meant to run in its own goroutine.
func (m *mapStateManager) run(ctx context.Context) {
	for {
		m.mu.Lock()
		target, tg, ag, setAt := m.target, m.targetGen, m.appliedGen, m.targetSetAt
		m.mu.Unlock()

		// Fully converged (or nothing yet): block until a new target arrives.
		if target == nil || ag == tg {
			select {
			case <-ctx.Done():
				return
			case <-m.wake:
				continue
			}
		}

		more, err := m.apply(target)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Errorf("apply sync pass: %v", err)
			// avoid a tight error loop; retry on the next target or after a short delay
			select {
			case <-ctx.Done():
				return
			case <-m.wake:
			case <-time.After(time.Second):
			}
			continue
		}

		if more {
			// keep converging the current target; syncMsgMux was released by apply
			// between passes so other subsystems interleave.
			continue
		}

		// This pass converged. Mark applied only if no newer target arrived during it.
		m.mu.Lock()
		converged := m.targetGen == tg
		if converged {
			m.appliedGen = tg
		}
		m.mu.Unlock()

		if converged && m.onConverged != nil {
			m.onConverged(time.Since(setAt))
		}
		// if a newer target arrived mid-pass, ag<tg next iteration -> apply it
	}
}
