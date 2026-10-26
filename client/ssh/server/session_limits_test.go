package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cryptossh "golang.org/x/crypto/ssh"
)

// A malformed window-change arriving after a valid one must not cost the valid resize:
// the valid request stays queued for the PTY, and only the malformed one is refused.
func TestRequestFilter_MalformedWinchKeepsQueuedValidResize(t *testing.T) {
	f := &requestFilter{}
	require.True(t, f.enqueue(&cryptossh.Request{Type: "shell"}))

	valid := &cryptossh.Request{Type: "window-change", Payload: cryptossh.Marshal(struct{ Columns, Rows, Width, Height uint32 }{100, 40, 0, 0})}
	require.True(t, f.enqueue(valid))

	malformed := &cryptossh.Request{Type: "window-change", Payload: []byte{1, 2, 3}}
	require.True(t, f.enqueue(malformed))

	assert.Equal(t, "window-change", valid.Type, "valid resize must still reach the PTY handler")
	assert.Equal(t, refusedRequestType, malformed.Type, "malformed resize must be refused")
}

// A zero-row or zero-column resize parses but would size the PTY to nothing, so it must
// not displace a valid queued resize either.
func TestRequestFilter_ZeroSizeWinchKeepsQueuedValidResize(t *testing.T) {
	f := &requestFilter{}
	require.True(t, f.enqueue(&cryptossh.Request{Type: "shell"}))

	valid := &cryptossh.Request{Type: "window-change", Payload: cryptossh.Marshal(struct{ Columns, Rows, Width, Height uint32 }{100, 40, 0, 0})}
	require.True(t, f.enqueue(valid))

	zeroRows := &cryptossh.Request{Type: "window-change", Payload: cryptossh.Marshal(struct{ Columns, Rows, Width, Height uint32 }{100, 0, 0, 0})}
	require.True(t, f.enqueue(zeroRows))

	assert.Equal(t, "window-change", valid.Type, "valid resize must still reach the PTY handler")
	assert.Equal(t, refusedRequestType, zeroRows.Type, "zero-row resize must be refused")
}

// Sizes that are zero or do not fit the PTY's uint16 dimensions are refused, so they
// cannot replace a valid queued resize.
func TestValidWinchPayload_RejectsUnusableSizes(t *testing.T) {
	tests := []struct {
		name          string
		columns, rows uint32
	}{
		{name: "zero columns", columns: 0, rows: 40},
		{name: "zero rows", columns: 100, rows: 0},
		{name: "columns wrap to zero as uint16", columns: 65536, rows: 40},
		{name: "rows wrap to zero as uint16", columns: 100, rows: 65536},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := cryptossh.Marshal(struct{ Columns, Rows, Width, Height uint32 }{tc.columns, tc.rows, 0, 0})
			assert.False(t, validWinchPayload(payload))
		})
	}
	assert.True(t, validWinchPayload(cryptossh.Marshal(struct{ Columns, Rows, Width, Height uint32 }{65535, 65535, 0, 0})), "largest uint16 size is usable")
}
