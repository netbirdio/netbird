package healthcheck

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIntervalFor(t *testing.T) {
	assert.Equal(t, 120*time.Second, IntervalFor("ws"), "the stream transport gets the long interval")
	assert.Equal(t, 25*time.Second, IntervalFor("quic"), "the datagram transport keeps the default interval")
	assert.Equal(t, 25*time.Second, IntervalFor(""), "an unknown transport keeps the default interval")
}

func TestHeartbeatTimeoutFor(t *testing.T) {
	assert.Equal(t, 130*time.Second, HeartbeatTimeoutFor("ws"), "the client allows the interval plus the grace")
	assert.Equal(t, 35*time.Second, HeartbeatTimeoutFor("quic"), "the default matches the v1 receiver timeout")
}
