package server

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/relay/auth/allow"
	"github.com/netbirdio/netbird/shared/relay/healthcheck"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

// alignedTestPeer runs a peer's real health check sender and writer on a
// scripted connection, without the relay around it. writes receives the
// time of every frame the peer writes.
func alignedTestPeer(t *testing.T, ctx context.Context, name string) (*Peer, *scriptedConn, *healthcheck.Sender, <-chan time.Time) {
	t.Helper()
	conn := newScriptedConn()
	writes := make(chan time.Time, 16)
	conn.onWrite = func([]byte) { writes <- time.Now() }
	p := NewPeer(nil, messages.HashID(name), messages.CurrentProtocolVersion, conn, nil, nil)
	hc := healthcheck.NewSender(p.log)
	go hc.StartHealthCheck(ctx)
	go p.handleHealthcheckEvents(ctx, hc)
	return p, conn, hc, writes
}

// answer feeds a client health check frame to the peer's message handler.
func answer(ctx context.Context, p *Peer, hc *healthcheck.Sender, frame []byte) {
	p.handleMsgType(ctx, messages.MsgTypeHealthCheck, hc, len(frame), frame)
}

// lastFrame returns the last frame the peer wrote.
func lastFrame(t *testing.T, conn *scriptedConn) []byte {
	t.Helper()
	frames := conn.frames()
	require.NotEmpty(t, frames, "the peer wrote no frame")
	return frames[len(frames)-1]
}

// Answers without a valid period keep the stock health checks byte for
// byte. A later answer with a period moves the sends to the peer's phase
// and every frame carries the period. Once the answers stop, the peer is
// closed.
func TestPeerAlignedHealthchecks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		p, conn, hc, writes := alignedTestPeer(t, ctx, "aligned-peer")
		start := time.Now()

		stock := messages.MarshalHealthcheck()
		answer(ctx, p, hc, stock)
		answer(ctx, p, hc, append(append([]byte(nil), stock...), 0x3c))
		answer(ctx, p, hc, messages.MarshalHealthcheckWithPeriod(0))
		at := <-writes
		assert.Equal(t, 25*time.Second, at.Sub(start), "a stock peer keeps the 25s interval")
		assert.Equal(t, stock, lastFrame(t, conn), "a stock peer gets the stock frame")
		answer(ctx, p, hc, stock)

		// 1 s is clamped to 30 s; the phase is the one Management and
		// Signal compute for the same peer.
		const period = 30 * time.Second
		phase := alignedhb.Phase(messages.HashID("aligned-peer"), period)
		withPeriod := messages.MarshalHealthcheckWithPeriod(1)
		var lastAnswer time.Time
		for i := 0; i < 3; i++ {
			answer(ctx, p, hc, withPeriod)
			lastAnswer = time.Now()
			at := <-writes
			assert.Equal(t, phase.Milliseconds(), at.UnixMilli()%period.Milliseconds(), "send %d on the phase", i)
			got, ok, err := messages.UnmarshalHealthcheckPeriod(lastFrame(t, conn))
			require.NoError(t, err)
			require.True(t, ok, "send %d carries the period", i)
			assert.Equal(t, uint16(30), got, "send %d carries the clamped period", i)
		}

		// No more answers: the peer is closed within two spans of
		// period plus 20 s after the last answer.
		for !conn.isClosed() {
			select {
			case <-writes:
			case <-conn.closed:
			}
		}
		assert.LessOrEqual(t, time.Since(lastAnswer), 2*(period+20*time.Second), "silent aligned peer closed")
	})
}

func TestPeerAlignedHealthchecksClampPeriod(t *testing.T) {
	for raw, want := range map[uint16]uint16{1: 30, 60: 60, 1000: 300} {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p, conn, hc, writes := alignedTestPeer(t, ctx, "clamp-peer")
			answer(ctx, p, hc, messages.MarshalHealthcheckWithPeriod(raw))
			<-writes
			got, ok, err := messages.UnmarshalHealthcheckPeriod(lastFrame(t, conn))
			require.NoError(t, err)
			require.True(t, ok, "raw period %d s: frame carries the period", raw)
			assert.Equal(t, want, got, "raw period %d s", raw)
		})
	}
}

// The aligned gauge counts a peer once it switches and stops when its
// connection ends.
func TestPeerAlignedGauge(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	relay, err := NewRelay(Config{
		Meter:          provider.Meter("test"),
		ExposedAddress: "rel://127.0.0.1:1234",
		AuthValidator:  &allow.Auth{},
	})
	require.NoError(t, err)
	t.Cleanup(func() { relay.Shutdown(context.Background()) })

	gauge := func() int64 {
		rm := &metricdata.ResourceMetrics{}
		require.NoError(t, reader.Collect(context.Background(), rm))
		var total int64
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				if m.Name != "relay_aligned_peers" {
					continue
				}
				sum, ok := m.Data.(metricdata.Sum[int64])
				if !ok {
					continue
				}
				for _, dp := range sum.DataPoints {
					total += dp.Value
				}
			}
		}
		return total
	}
	assert.Equal(t, int64(0), gauge())

	conn, _ := acceptPeer(t, relay, "gauge-peer")
	assert.Equal(t, int64(0), gauge(), "a stock peer is not counted")

	frame := messages.MarshalHealthcheckWithPeriod(60)
	conn.deliver(t, frame)
	require.Eventually(t, func() bool { return gauge() == 1 }, 2*time.Second, 10*time.Millisecond,
		"the switched peer is counted")

	require.NoError(t, conn.Close())
	assert.Eventually(t, func() bool { return gauge() == 0 }, 2*time.Second, 10*time.Millisecond,
		"the ended peer is uncounted")
}
