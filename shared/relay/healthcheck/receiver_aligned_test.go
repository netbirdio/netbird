package healthcheck

import (
	"testing"
	"testing/synctest"
	"time"

	log "github.com/sirupsen/logrus"
)

// A receiver created with a timeout waits that long for the first heartbeat, not the stock
// timeout, and a heartbeat in time keeps it alive for one more timeout.
func TestReceiverWithTimeout(t *testing.T) {
	// The timing below expects the default of one failed attempt.
	t.Setenv(defaultAttemptThresholdEnv, "1")
	synctest.Test(t, func(t *testing.T) {
		const timeout = 70 * time.Second
		r := NewReceiverWithTimeout(log.WithField("test", t.Name()), timeout)
		defer r.Stop()
		start := time.Now()

		time.Sleep(timeout - time.Second)
		r.Heartbeat()
		<-r.OnTimeout
		if since := time.Since(start); since != 2*timeout {
			t.Fatalf("timed out %s after the start, want %s: one heartbeat keeps one more timeout", since, 2*timeout)
		}
	})
}
