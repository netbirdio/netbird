//go:build (linux && !android) || freebsd

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPickXorgCandidate covers which X server a service-mode capturer attaches
// to when several are running. Picking the wrong one shows a remote user
// another local user's screen, so the active VT wins whenever it is known.
func TestPickXorgCandidate(t *testing.T) {
	tests := []struct {
		name       string
		candidates []xorgCandidate
		activeVT   int
		want       string
		wantOK     bool
	}{
		{
			name:   "no X server found",
			wantOK: false,
		},
		{
			name:       "single server is used whatever its VT",
			candidates: []xorgCandidate{{display: ":3", vt: 9}},
			activeVT:   2,
			want:       ":3",
			wantOK:     true,
		},
		{
			name: "active VT wins over the lower display number",
			candidates: []xorgCandidate{
				{display: ":0", vt: 2},
				{display: ":1", vt: 7},
			},
			activeVT: 7,
			want:     ":1",
			wantOK:   true,
		},
		{
			name: "unknown active VT falls back to the lowest display",
			candidates: []xorgCandidate{
				{display: ":1", vt: 7},
				{display: ":0", vt: 2},
			},
			activeVT: -1,
			want:     ":0",
			wantOK:   true,
		},
		{
			name: "display numbers compare numerically, not lexically",
			candidates: []xorgCandidate{
				{display: ":10", vt: -1},
				{display: ":2", vt: -1},
			},
			activeVT: -1,
			want:     ":2",
			wantOK:   true,
		},
		{
			name: "an unparseable display is only picked when it is alone",
			candidates: []xorgCandidate{
				{display: ":bogus", vt: -1},
				{display: ":4", vt: -1},
			},
			activeVT: -1,
			want:     ":4",
			wantOK:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := pickXorgCandidate(tc.candidates, tc.activeVT)
			require.Equal(t, tc.wantOK, ok)
			if !tc.wantOK {
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
