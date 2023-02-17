package status

import (
	"testing"
)

func Test_notifier_serverState(t *testing.T) {

	type scenario struct {
		name        string
		expected    bool
		mgmState    bool
		signalState bool
	}
	scenarios := []scenario{
		{"connected", true, true, true},
		{"mgm down", false, false, true},
		{"signal down", false, true, false},
		{"disconnected", false, false, false},
	}

	for _, tt := range scenarios {
		t.Run(tt.name, func(t *testing.T) {
			n := newNotifier()
			n.updateServerStates(tt.mgmState, tt.signalState)
			if n.currentServerState != tt.expected {
				t.Errorf("invalid serverstate: %t, expected: %t", n.currentServerState, tt.expected)
			}

		})
	}
}
