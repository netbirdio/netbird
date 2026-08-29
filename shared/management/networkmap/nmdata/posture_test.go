package nmdata

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func bundle(def ChecksDefinition) []*PostureChecks {
	return []*PostureChecks{{Checks: def}}
}

func TestPostureVerdictChanged_ErrorCountsAsDeny(t *testing.T) {
	c := bundle(ChecksDefinition{NBVersionCheck: &NBVersionCheck{MinVersion: "1.2.0"}})

	tests := []struct {
		name           string
		oldVer, newVer string
		want           bool
	}{
		{"both above min, no flip", "1.3.0", "1.4.0", false},
		{"crosses up below->above", "1.1.0", "1.3.0", true},
		{"unparsable old only -> flip", "garbage", "1.3.0", true},
		{"unparsable both -> no flip", "garbage", "junk", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldPeer := &Peer{Meta: PeerSystemMeta{WtVersion: tt.oldVer}}
			newPeer := &Peer{Meta: PeerSystemMeta{WtVersion: tt.newVer}}
			assert.Equal(t, tt.want, PostureVerdictChanged(c, oldPeer, newPeer))
		})
	}
}

func TestPostureVerdictChanged_ReplaysEachCheck(t *testing.T) {
	// Old fails the version check, new fails the kernel check: the bundle denies on
	// both sides, yet every single check flipped, so the posture must be re-evaluated.
	c := bundle(ChecksDefinition{
		NBVersionCheck: &NBVersionCheck{MinVersion: "1.0.0"},
		OSVersionCheck: &OSVersionCheck{Linux: &MinKernelVersionCheck{MinKernelVersion: "5.0.0"}},
	})
	oldPeer := &Peer{Meta: PeerSystemMeta{WtVersion: "0.9.0", GoOS: "linux", KernelVersion: "6.0.0"}}
	newPeer := &Peer{Meta: PeerSystemMeta{WtVersion: "1.1.0", GoOS: "linux", KernelVersion: "4.0.0"}}

	assert.False(t, c[0].Passes(oldPeer))
	assert.False(t, c[0].Passes(newPeer))
	assert.True(t, PostureVerdictChanged(c, oldPeer, newPeer))
}

func TestPostureVerdictChanged_NoChecks(t *testing.T) {
	oldPeer := &Peer{Meta: PeerSystemMeta{WtVersion: "1.0.0"}}
	newPeer := &Peer{Meta: PeerSystemMeta{WtVersion: "2.0.0"}}
	assert.False(t, PostureVerdictChanged(nil, oldPeer, newPeer))
}
