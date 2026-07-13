package guard

import (
	"testing"

	log "github.com/sirupsen/logrus"
)

func newTestRetryState() *iceRetryState {
	return &iceRetryState{log: log.NewEntry(log.StandardLogger())}
}

func TestICERetryState_AllowsInitialBudget(t *testing.T) {
	s := newTestRetryState()

	for i := 1; i <= maxICERetries; i++ {
		if !s.shouldRetry() {
			t.Fatalf("shouldRetry returned false on attempt %d, want true (budget = %d)", i, maxICERetries)
		}
	}
}

func TestICERetryState_ExhaustsAfterBudget(t *testing.T) {
	s := newTestRetryState()

	for i := 0; i < maxICERetries; i++ {
		_ = s.shouldRetry()
	}

	if s.shouldRetry() {
		t.Fatalf("shouldRetry returned true after budget exhausted, want false")
	}
}

func TestICERetryState_HourlyCNilBeforeEnterHourlyMode(t *testing.T) {
	s := newTestRetryState()

	if s.hourlyC() != nil {
		t.Fatalf("hourlyC returned non-nil channel before enterHourlyMode")
	}
}

func TestICERetryState_EnterHourlyModeArmsTicker(t *testing.T) {
	s := newTestRetryState()
	for i := 0; i < maxICERetries+1; i++ {
		_ = s.shouldRetry()
	}

	s.enterHourlyMode()
	defer s.reset()

	if s.hourlyC() == nil {
		t.Fatalf("hourlyC returned nil after enterHourlyMode")
	}
}

func TestICERetryState_ShouldRetryTrueInHourlyMode(t *testing.T) {
	s := newTestRetryState()
	s.enterHourlyMode()
	defer s.reset()

	if !s.shouldRetry() {
		t.Fatalf("shouldRetry returned false in hourly mode, want true")
	}

	// Subsequent calls also return true — we keep retrying on each hourly tick.
	if !s.shouldRetry() {
		t.Fatalf("second shouldRetry returned false in hourly mode, want true")
	}
}

func TestICERetryState_ResetRestoresBudget(t *testing.T) {
	s := newTestRetryState()
	for i := 0; i < maxICERetries+1; i++ {
		_ = s.shouldRetry()
	}
	s.enterHourlyMode()

	s.reset()

	if s.hourlyC() != nil {
		t.Fatalf("hourlyC returned non-nil channel after reset")
	}
	if s.retries != 0 {
		t.Fatalf("retries = %d after reset, want 0", s.retries)
	}

	for i := 1; i <= maxICERetries; i++ {
		if !s.shouldRetry() {
			t.Fatalf("shouldRetry returned false on attempt %d after reset, want true", i)
		}
	}
}

func TestICERetryState_ResetIsIdempotent(t *testing.T) {
	s := newTestRetryState()
	s.reset()
	s.reset() // second call must not panic or re-stop a nil ticker

	if s.hourlyC() != nil {
		t.Fatalf("hourlyC non-nil after double reset")
	}
}
