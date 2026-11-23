package healthcheck

import (
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

// TestReceiverSetTimeoutSwitchesToAlignedTimeout covers the relay client
// switch: a receiver created with the stock timeout times out at the
// aligned one after SetTimeout, and not before.
func TestReceiverSetTimeoutSwitchesToAlignedTimeout(t *testing.T) {
	r := NewReceiverWithOpts(log.WithField("test", "aligned"), ReceiverOptions{
		HeartbeatTimeout: time.Hour,
		AttemptThreshold: 1,
	})
	defer r.Stop()

	select {
	case <-r.OnTimeout:
		t.Fatal("timed out on the stock timeout")
	case <-time.After(100 * time.Millisecond):
	}

	r.SetTimeout(50 * time.Millisecond)
	select {
	case <-r.OnTimeout:
	case <-time.After(5 * time.Second):
		t.Fatal("no timeout after the aligned timeout was set")
	}

	r.SetTimeout(0)
	r.SetTimeout(-time.Second)
}
