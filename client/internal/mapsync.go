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
// coalesces: it keeps converging toward the latest target rather than replaying
// the intermediate ones.
//
// Convergence is a single comparison: appliedGen == targetGen. targetGen
// increments on every SetTarget (an internal generation counter, so it also covers
// config-only updates that carry no network-map serial).
//
// onConverged still fires once per MAP, not once per convergence: every update's
// receive time is recorded in `pending` and the whole list is drained on each
// settle. So a map that was superseded mid-flight (its apply coalesced into a newer
// target) still gets its finish-sync signal when the client reaches a converged
// state covering it — the signal is delayed at worst, never lost. That log/metric
// is a strong problem indicator and must not silently disappear.
type mapStateManager struct {
	// apply performs one bounded apply pass and reports whether more passes are needed.
	apply func(*mgmProto.SyncResponse) (bool, error)
	// onConverged is called once per applied map, with the elapsed time since that
	// map was received (for the sync-duration metric / "sync finished" log).
	onConverged func(time.Duration)

	mu         sync.Mutex
	target     *mgmProto.SyncResponse
	targetGen  uint64
	appliedGen uint64
	// pending holds the receive time of every update accepted since the last settle,
	// oldest first. Drained on convergence so onConverged fires once per map.
	pending []time.Time

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
	m.pending = append(m.pending, time.Now())
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
		target, tg, ag := m.target, m.targetGen, m.appliedGen
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
			// Log and DROP this target — do not retry it. A deterministic failure
			// (e.g. a malformed peer in the map) would otherwise spin every pass
			// making no progress. Management is the source of truth and re-delivers
			// the full map on the next sync, so dropping is safe; peers already
			// applied this convergence stay (idempotent diffs) and the remainder is
			// reconciled by the next target. Mirrors the legacy handleSync path,
			// where the apply error was logged by the gRPC client and the update
			// dropped. No onConverged: this target did not converge.
			log.Errorf("apply sync pass, dropping update: %v", err)
			m.settle(tg, false)
			continue
		}

		if more {
			// keep converging the current target; syncMsgMux was released by apply
			// between passes so other subsystems interleave.
			continue
		}

		// This pass converged. Mark applied + signal every pending map.
		m.settle(tg, true)
		// if a newer target arrived mid-pass, settle is a no-op (targetGen != tg) and
		// ag<tg next iteration -> apply it; pending carries over until the next settle.
	}
}

// settle marks generation tg as processed so the loop goes idle instead of
// re-applying the same target. It is a no-op when a newer target arrived during the
// pass (targetGen != tg), leaving appliedGen + pending behind so that target
// re-applies and its maps are signaled at the next settle.
//
// When signal is true (the pass converged) it drains pending and fires onConverged
// once per map. When false (the target was dropped on error) it discards pending
// without signaling — those maps did not converge; management re-delivers them.
func (m *mapStateManager) settle(tg uint64, signal bool) {
	m.mu.Lock()
	if m.targetGen != tg {
		m.mu.Unlock()
		return
	}
	m.appliedGen = tg
	toSignal := m.pending
	m.pending = nil
	m.mu.Unlock()

	if signal && m.onConverged != nil {
		for _, setAt := range toSignal {
			m.onConverged(time.Since(setAt))
		}
	}
}
