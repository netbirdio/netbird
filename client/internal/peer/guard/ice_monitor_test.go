package guard

import (
	"testing"

	icemaker "github.com/netbirdio/netbird/client/internal/peer/ice"
	"github.com/pion/ice/v4"
	"github.com/pion/stun/v3"
)

// mockCandidate implements ice.Candidate for testing
type mockCandidate struct {
	ice.Candidate // Embedded interface allows us to ignore unneeded methods
	address       string
}

func (m mockCandidate) Address() string {
	return m.address
}

func TestICEMonitor_updateCandidates_InitialGatherPopulatesBaseline(t *testing.T) {
	cm := &ICEMonitor{}

	hostCandidate := mockCandidate{address: "192.168.1.100"}
	srflxCandidate := mockCandidate{address: "203.0.113.50"}

	// 1. First successful gather establishes the baseline.
	// This simulates the first tick after STUN config becomes available.
	changed := cm.updateCandidates([]ice.Candidate{
		hostCandidate,
		srflxCandidate,
	})

	if changed {
		t.Errorf("First gather should populate baseline without reporting change")
	}
	if !cm.baselineInitialized {
		t.Errorf("Baseline should be marked as initialized")
	}
	if len(cm.currentCandidatesAddress) != 2 {
		t.Errorf("Baseline was not populated correctly")
	}

	// 2. Second gather: identical candidates
	// Should not report change
	changed = cm.updateCandidates([]ice.Candidate{hostCandidate, srflxCandidate})
	if changed {
		t.Errorf("Subsequent gather with identical candidates should not report change")
	}

	// 3. Third gather: new candidate added (genuine network change)
	newHostCandidate := mockCandidate{address: "10.0.0.5"}
	changed = cm.updateCandidates([]ice.Candidate{hostCandidate, srflxCandidate, newHostCandidate})
	if !changed {
		t.Errorf("Subsequent gather with new candidates should report change")
	}
}

func TestICEMonitor_hasStunTurnConfig(t *testing.T) {
	tests := []struct {
		name     string
		stunTurn *icemaker.StunTurn
		setup    func(*icemaker.StunTurn)
		expected bool
	}{
		{
			name:     "Nil StunTurn pointer",
			stunTurn: nil,
			setup:    func(st *icemaker.StunTurn) {},
			expected: false,
		},
		{
			name:     "StunTurn pointer not nil but Load returns nil",
			stunTurn: &icemaker.StunTurn{},
			setup:    func(st *icemaker.StunTurn) {}, // atomic.Value implicitly holds nil
			expected: false,
		},
		{
			name:     "StunTurn populated",
			stunTurn: &icemaker.StunTurn{},
			setup: func(st *icemaker.StunTurn) {
				st.Store([]*stun.URI{{Scheme: stun.SchemeTypeSTUN, Host: "stun.netbird.io"}})
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cm := &ICEMonitor{
				iceConfig: icemaker.Config{
					StunTurn: tt.stunTurn,
				},
			}
			tt.setup(tt.stunTurn)

			if got := cm.hasStunTurnConfig(); got != tt.expected {
				t.Errorf("hasStunTurnConfig() = %v, want %v", got, tt.expected)
			}
		})
	}
}
