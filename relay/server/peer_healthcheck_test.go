package server

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/relay/auth/allow"
	"github.com/netbirdio/netbird/shared/relay/healthcheck"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

var errWriteFailed = errors.New("write failed")

type failingWriteConn struct {
	*scriptedConn
}

func (c *failingWriteConn) Write(context.Context, []byte) (int, error) {
	return 0, errWriteFailed
}

func TestPeer_HealthcheckWriteErrorClosesConnection(t *testing.T) {
	relay := newTestRelay(t, &allow.Auth{})
	conn := &failingWriteConn{scriptedConn: newScriptedConn()}
	peer := NewPeer(relay.metrics, messages.HashID("peer"), messages.CurrentProtocolVersion, conn, relay.store, relay.notifier)
	hc := healthcheck.NewSender(peer.log)
	hc.HealthCheck <- struct{}{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		peer.handleHealthcheckEvents(context.Background(), hc)
	}()

	require.True(t, signaled(done), "the healthcheck handler must stop after a write error")
	assert.True(t, conn.isClosed(), "a failed healthcheck write must close the connection")
}

func TestPeer_HealthcheckHandlerAfterSenderExit(t *testing.T) {
	cases := []struct {
		name     string
		timedOut bool
	}{
		{"sender timed out", true},
		{"sender was cancelled", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			relay := newTestRelay(t, &allow.Auth{})

			// The handler picks among the ready channels at random, so a single run
			// cannot show every order.
			for range 50 {
				conn := newScriptedConn()
				peer := NewPeer(relay.metrics, messages.HashID("peer"), messages.CurrentProtocolVersion, conn, relay.store, relay.notifier)
				hc := healthcheck.NewSender(peer.log)
				if tc.timedOut {
					hc.Timeout <- struct{}{}
				}
				close(hc.HealthCheck)
				close(hc.Timeout)

				done := make(chan struct{})
				go func() {
					defer close(done)
					peer.handleHealthcheckEvents(context.Background(), hc)
				}()

				require.True(t, signaled(done), "the healthcheck handler must stop once the sender has exited")
				assert.Empty(t, conn.frames(), "no healthcheck may be written after the sender has exited")
				assert.Equal(t, tc.timedOut, conn.isClosed(), "the connection must be closed only on a timeout")
			}
		})
	}
}
