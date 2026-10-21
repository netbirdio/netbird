package networkmonitor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInterfaceStatesChanged(t *testing.T) {
	tests := []struct {
		name    string
		before  interfaceStates
		after   interfaceStates
		changed bool
		index   int
	}{
		{name: "nothing moved", before: interfaceStates{12: true, 13: true}, after: interfaceStates{12: true, 13: true}},
		// Cable unplugged: the adapter stays listed but is no longer up.
		{name: "interface goes down", before: interfaceStates{12: true, 13: true}, after: interfaceStates{12: true, 13: false}, changed: true, index: 13},
		// Cable plugged back in.
		{name: "interface comes up", before: interfaceStates{12: true, 13: false}, after: interfaceStates{12: true, 13: true}, changed: true, index: 13},
		// A USB adapter or dock appears already connected.
		{name: "new interface up", before: interfaceStates{12: true}, after: interfaceStates{12: true, 14: true}, changed: true, index: 14},
		{name: "new interface down is not a change", before: interfaceStates{12: true}, after: interfaceStates{12: true, 14: false}},
		// A USB adapter or dock is pulled while in use.
		{name: "up interface disappears", before: interfaceStates{12: true, 14: true}, after: interfaceStates{12: true}, changed: true, index: 14},
		{name: "down interface disappears is not a change", before: interfaceStates{12: true, 14: false}, after: interfaceStates{12: true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			index, changed := tt.before.changed(tt.after)
			assert.Equal(t, tt.changed, changed, "changed verdict")
			if tt.changed {
				assert.Equal(t, tt.index, index, "reported interface")
			}
		})
	}
}
