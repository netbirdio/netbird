package peer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/peer/metricsstages"
	"github.com/netbirdio/netbird/client/internal/peer/signaling"
)

func TestConn_AnswerBeforeEventLoop(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ports []int
	}{
		{name: "holds early answer", ports: []int{51820}},
		{name: "keeps latest answer", ports: []int{1111, 2222}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := NewConn(connConf, ServiceDependencies{})
			require.NoError(t, err)
			conn.metricsStages = &metricsstages.MetricsStages{}
			conn.handshaker = signaling.NewHandshaker(conn.Log, signaling.Config{}, nil, nil, nil)
			// A relay dial in progress retains the dispatched answer as its next offer.
			conn.relayDialInFlight = true
			mb := newMailbox()
			conn.mailbox.Store(mb)

			// Incoming answers can arrive after Open publishes the mailbox but
			// before the event loop gets scheduled to consume it.
			for _, port := range tc.ports {
				conn.OnRemoteAnswer(signaling.OfferAnswer{WgListenPort: port})
			}

			select {
			case <-mb.wake:
			default:
				t.Fatal("an early answer must wake the event loop")
			}
			events := mb.drain()
			require.Len(t, events, 1, "only the latest answer should reach the event loop")
			for _, ev := range events {
				conn.handleEvent(ev)
			}
			require.NotNil(t, conn.pendingRelayOffer, "the answer must reach relay dispatch")
			assert.Equal(t, tc.ports[len(tc.ports)-1], conn.pendingRelayOffer.WgListenPort,
				"relay dispatch must receive the latest queued answer")
		})
	}
}
