package peer

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type closeTestWGIface struct{ WGIface }

func (closeTestWGIface) RemovePeer(string) error { return nil }

// Close must let an in-flight handshake acquire mu and exit before waiting for it.
func TestConnCloseDuringICEOffer(t *testing.T) {
	w := newTestWorkerICE(t)
	conn, _ := connectedCallbackTestConn()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	conn.ctx = ctx
	w.ctx = ctx
	w.conn = conn
	conn.workerICE = w
	conn.workerRelay = &WorkerRelay{}
	conn.endpointUpdater = NewEndpointUpdater(conn.Log, WgConfig{WgInterface: closeTestWGIface{}}, false)
	conn.opened = true

	entered := make(chan struct{})
	h := NewHandshaker(conn.Log, w.config, w.signaler, w, conn.workerRelay, conn.metricsStages)
	h.AddICEListener(func(offer *OfferAnswer) {
		close(entered)
		<-ctx.Done() // Close owns conn.mu before allowing OnNewOffer to proceed.
		w.OnNewOffer(offer)
	})
	conn.wg.Add(1)
	go func() {
		defer conn.wg.Done()
		h.Listen(ctx)
	}()
	h.remoteAnswerCh <- OfferAnswer{IceCredentials: IceCredentials{UFrag: "testufrag", Pwd: "testpwdtestpwdtestpwd12"}}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("handshake did not start")
	}
	conn.ctxCancel = cancel
	done := make(chan struct{})
	go func() {
		conn.Close(false)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close deadlocked with the in-flight ICE offer")
	}
	w.muxAgent.Lock()
	defer w.muxAgent.Unlock()
	require.Nil(t, w.agent, "queued offers must not create an agent after shutdown")
	require.False(t, w.agentConnecting)
}
