package peer

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	log "github.com/sirupsen/logrus"

	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
)

func newTestWorkerICE(t *testing.T) *WorkerICE {
	t.Helper()
	cfg := ConnConfig{
		Key:      "LLHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		LocalKey: "RRHf3Ma6z6mdLbriAJbqhX7+nM/B71lgw2+91q3LfhU=",
		ICEConfig: icemaker.Config{
			StunTurn: &icemaker.StunTurn{},
		},
	}
	w, err := NewWorkerICE(context.Background(), log.WithField("peer", "test"), cfg, nil, nil, nil, NewRecorder("https://mgm"), false)
	if err != nil {
		t.Fatalf("failed to create ICE worker: %v", err)
	}
	return w
}

// newClosedTestAgent returns an ICE agent that is already closed, so
// GatherCandidates deterministically fails and connect takes its first
// error path without any network activity.
func newClosedTestAgent(t *testing.T, w *WorkerICE) *icemaker.ThreadSafeAgent {
	t.Helper()
	agent, err := icemaker.NewAgent(context.Background(), nil, w.config.ICEConfig, icemaker.CandidateTypes(), w.localUfrag, w.localPwd)
	if err != nil {
		t.Fatalf("failed to create ICE agent: %v", err)
	}
	if err := agent.Close(); err != nil {
		t.Fatalf("failed to close ICE agent: %v", err)
	}
	return agent
}

// TestWorkerICE_ConnectErrorPathUsesOwnDialerCancel pins that a failing
// connect attempt cancels its own dialer context and never invokes the
// worker-level agentDialerCancel, which may already belong to a successor
// dial started by a concurrent OnNewOffer.
func TestWorkerICE_ConnectErrorPathUsesOwnDialerCancel(t *testing.T) {
	w := newTestWorkerICE(t)
	agent := newClosedTestAgent(t, w)

	var successorCancelled atomic.Bool
	w.agentDialerCancel = func() { successorCancelled.Store(true) }

	ownCtx, cancelFn := context.WithCancel(context.Background())
	defer cancelFn()
	var ownCancelled atomic.Bool
	ownCancel := func() {
		ownCancelled.Store(true)
		cancelFn()
	}

	w.connect(ownCtx, agent, ownCancel, &OfferAnswer{})

	if successorCancelled.Load() {
		t.Fatal("connect error path must not invoke the shared agentDialerCancel field")
	}
	if !ownCancelled.Load() {
		t.Fatal("connect error path must cancel its own dialer context")
	}
}

// TestWorkerICE_ConnectDoesNotRaceOnDialerCancel runs connect concurrently
// with the field replacement OnNewOffer performs under muxAgent. Run with
// -race: before the fix, connect read the field without the lock, which the
// race detector reports.
func TestWorkerICE_ConnectDoesNotRaceOnDialerCancel(t *testing.T) {
	w := newTestWorkerICE(t)
	agent := newClosedTestAgent(t, w)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		w.connect(ctx, agent, cancel, &OfferAnswer{})
	}()
	go func() {
		defer wg.Done()
		// mirror OnNewOffer's field replacement under muxAgent
		w.muxAgent.Lock()
		w.agentDialerCancel = func() {}
		w.muxAgent.Unlock()
	}()
	wg.Wait()
}
