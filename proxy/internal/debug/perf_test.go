package debug

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	nbembed "github.com/netbirdio/netbird/client/embed"
	"github.com/netbirdio/netbird/proxy/internal/health"
	"github.com/netbirdio/netbird/proxy/internal/roundtrip"
	"github.com/netbirdio/netbird/proxy/internal/types"
)

// perfProvider serves a fixed set of accounts. The clients are nil: the tests
// drive Handler.setPerformance, which never dereferences them.
type perfProvider struct {
	accounts []types.AccountID
}

func (p *perfProvider) GetClient(types.AccountID) (*nbembed.Client, bool) { return nil, false }

func (p *perfProvider) ListClientsForDebug() map[types.AccountID]roundtrip.ClientDebugInfo {
	return nil
}

func (p *perfProvider) ListClientsForStartup() map[types.AccountID]*nbembed.Client {
	out := make(map[types.AccountID]*nbembed.Client, len(p.accounts))
	for _, id := range p.accounts {
		out[id] = nil
	}
	return out
}

type stubHealth struct{}

func (stubHealth) ReadinessProbe() bool              { return true }
func (stubHealth) StartupProbe(context.Context) bool { return true }
func (stubHealth) CheckClientsConnected(context.Context) (bool, map[types.AccountID]health.ClientHealth) {
	return true, nil
}

func shortenPerfTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	prev := perfApplyTimeout
	perfApplyTimeout = d
	t.Cleanup(func() { perfApplyTimeout = prev })
}

// TestCollectBufferedCountsResultsReadyAtTheDeadline covers the select-ordering
// trap: when the deadline fires, results already buffered must be counted, not
// reported as timeouts. Driving collectBuffered directly keeps it deterministic
// - through applyBufferCap the two select cases race by construction.
func TestCollectBufferedCountsResultsReadyAtTheDeadline(t *testing.T) {
	results := make(chan perfResult, 3)
	results <- perfResult{accountID: "ok"}
	results <- perfResult{accountID: "broken", err: errors.New("boom")}

	pending := map[types.AccountID]struct{}{"ok": {}, "broken": {}, "wedged": {}}
	failed := map[string]string{}

	applied := collectBuffered(results, pending, failed)

	if applied != 1 {
		t.Fatalf("applied = %d, want 1", applied)
	}
	if failed["broken"] != "boom" {
		t.Fatalf("failed = %v, want the error recorded for \"broken\"", failed)
	}
	if _, ok := pending["wedged"]; !ok || len(pending) != 1 {
		t.Fatalf("pending = %v, want only the account that never answered", pending)
	}
}

// TestApplyBufferCapSingleFlightPerAccount covers the goroutine accumulation
// reported on PR #7452: repeated calls against a client stuck in its own lock
// must not start a second attempt for the same account.
func TestApplyBufferCapSingleFlightPerAccount(t *testing.T) {
	shortenPerfTimeout(t, 50*time.Millisecond)

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })

	var calls atomic.Int32
	h := &Handler{
		provider: &perfProvider{accounts: []types.AccountID{"wedged"}},
		health:   stubHealth{},
		setPerformance: func(_ *nbembed.Client, _ uint32) error {
			calls.Add(1)
			<-release
			return nil
		},
	}

	for i := range 5 {
		applied, failed, inFlight := h.applyBufferCap(4096)
		if applied != 0 {
			t.Fatalf("call %d: applied = %d, want 0", i, applied)
		}
		if i == 0 {
			if len(failed) != 1 {
				t.Fatalf("first call: failed = %v, want the account reported as timed out", failed)
			}
			continue
		}
		if len(inFlight) != 1 {
			t.Fatalf("call %d: inFlight = %v, want the account reported as still running", i, inFlight)
		}
		if len(failed) != 0 {
			t.Fatalf("call %d: failed = %v, want empty while the retune is in flight", i, failed)
		}
	}

	if got := calls.Load(); got != 1 {
		t.Fatalf("setPerformance called %d times, want 1: each retry started another blocked worker", got)
	}
}
