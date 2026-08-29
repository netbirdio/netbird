//go:build (linux && !android) || freebsd

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPickXorgCandidate covers which X server a service-mode capturer attaches
// to when several are running. Picking the wrong one shows a remote user
// another local user's screen and delivers their input to it, so the active VT
// wins whenever it is known and an unresolvable choice is refused outright.
func TestPickXorgCandidate(t *testing.T) {
	tests := []struct {
		name        string
		candidates  []xorgCandidate
		activeVT    int
		want        string
		wantOutcome x11Detection
	}{
		{
			name:        "no X server found",
			wantOutcome: x11NotFound,
		},
		{
			name:        "single server is used whatever its VT",
			candidates:  []xorgCandidate{{display: ":3", vt: 9}},
			activeVT:    2,
			want:        ":3",
			wantOutcome: x11Detected,
		},
		{
			name: "active VT wins over the lower display number",
			candidates: []xorgCandidate{
				{display: ":0", vt: 2},
				{display: ":1", vt: 7},
			},
			activeVT:    7,
			want:        ":1",
			wantOutcome: x11Detected,
		},
		{
			name: "several servers on other VTs are refused, not guessed at",
			candidates: []xorgCandidate{
				{display: ":0", vt: 2},
				{display: ":1", vt: 3},
			},
			activeVT:    7,
			wantOutcome: x11Ambiguous,
		},
		{
			name: "unknown active VT does not license a guess between seats",
			candidates: []xorgCandidate{
				{display: ":0", vt: 2},
				{display: ":1", vt: 3},
			},
			activeVT:    -1,
			wantOutcome: x11Ambiguous,
		},
		{
			name: "a VT-less server is preferred over one on an inactive VT",
			candidates: []xorgCandidate{
				{display: ":0", vt: 2},
				{display: ":99", vt: -1},
			},
			activeVT:    7,
			want:        ":99",
			wantOutcome: x11Detected,
		},
		{
			name: "display numbers compare numerically, not lexically",
			candidates: []xorgCandidate{
				{display: ":10", vt: -1},
				{display: ":2", vt: -1},
			},
			activeVT:    -1,
			want:        ":2",
			wantOutcome: x11Detected,
		},
		{
			name: "an unparseable display is only picked when it is alone",
			candidates: []xorgCandidate{
				{display: ":bogus", vt: -1},
				{display: ":4", vt: -1},
			},
			activeVT:    -1,
			want:        ":4",
			wantOutcome: x11Detected,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, outcome := pickXorgCandidate(tc.candidates, tc.activeVT)
			require.Equal(t, tc.wantOutcome, outcome)
			if tc.wantOutcome != x11Detected {
				assert.Empty(t, got.display, "a refused choice must not leak a display")
				return
			}
			assert.Equal(t, tc.want, got.display)
		})
	}
}

// TestParseXorgVT confirms the bare "vt7" token X servers carry in argv is the
// one read, and that nothing else in the command line is mistaken for it.
func TestParseXorgVT(t *testing.T) {
	assert.Equal(t, 7, parseXorgVT([]string{"/usr/lib/Xorg", ":0", "-auth", "/run/x.auth", "vt7", "-novtswitch"}))
	assert.Equal(t, -1, parseXorgVT([]string{"/usr/bin/Xvfb", ":99", "-screen", "0", "1920x1080x24"}))
	assert.Equal(t, -1, parseXorgVT([]string{"/usr/lib/Xorg", ":0", "vtconsole"}))
}

// TestDescribeActiveVT keeps "we could not read the active VT" legible in the
// log line, rather than printing a -1 that reads like a real terminal.
func TestDescribeActiveVT(t *testing.T) {
	assert.Equal(t, "unknown", describeActiveVT(-1))
	assert.Equal(t, "unknown", describeActiveVT(0))
	assert.Equal(t, "tty7", describeActiveVT(7))
}
