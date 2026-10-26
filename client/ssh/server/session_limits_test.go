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
