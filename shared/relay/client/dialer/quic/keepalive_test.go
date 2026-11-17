package quic

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func setAlignedHeartbeat(t *testing.T, on bool) {
	t.Helper()
	prev := alignedHeartbeat
	alignedHeartbeat = func() bool { return on }
	t.Cleanup(func() { alignedHeartbeat = prev })
}

func TestKeepAlivePeriod(t *testing.T) {
	setAlignedHeartbeat(t, false)
	assert.Equal(t, 30*time.Second, keepAlivePeriod(), "a client without the aligned heartbeat keeps the stock QUIC ping")

	setAlignedHeartbeat(t, true)
	assert.Zero(t, keepAlivePeriod(), "an aligned heartbeat client sends no QUIC ping")
}

func TestKeepAlivePeriodOnThisBuild(t *testing.T) {
	// Desktop builds never ask for the aligned heartbeat, so they must ping.
	assert.Equal(t, stockKeepAlivePeriod, keepAlivePeriod(), "desktop build QUIC ping")
}
