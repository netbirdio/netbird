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

// alignedTestPeer runs a peer's real health check sender and writer on a scripted connection,
// without the relay around it, with the period the handshake accepted. writes receives the
// time of every frame the peer writes.
func alignedTestPeer(t *testing.T, ctx context.Context, name string, period time.Duration) (*Peer, *scriptedConn, *healthcheck.Sender, <-chan time.Time) {
	t.Helper()
	conn := newScriptedConn()
	writes := make(chan time.Time, 16)
	conn.onWrite = func([]byte) { writes <- time.Now() }
	p := NewPeer(nil, messages.HashID(name), messages.ProtocolV2, conn, nil, nil)
	p.alignedPeriod = period
	hc := p.newHealthcheckSender()
	go hc.StartHealthCheck(ctx)
	go p.handleHealthcheckEvents(ctx, hc)
	return p, conn, hc, writes
}

// answer feeds a client health check frame to the peer's message handler.
func answer(ctx context.Context, p *Peer, hc *healthcheck.Sender, frame []byte) {
	p.handleMsgType(ctx, messages.MsgTypeHealthCheck, hc, frame, nil)
}

// A peer whose handshake accepted a period sends stock health check frames on its phase from
// the start, with no send at connect, and is closed once the answers stop.
func TestPeerAlignedHealthchecksFromStart(t *testing.T) {
	// The close check below expects the default of one failed attempt.
	t.Setenv("NB_RELAY_HC_ATTEMPT_THRESHOLD", "1")
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		const period = 60 * time.Second
		p, conn, hc, writes := alignedTestPeer(t, ctx, "aligned-peer", period)
		phase := alignedhb.Phase(messages.HashID("aligned-peer"), period)
		start := time.Now()
		stock := messages.NewEncoder(messages.ProtocolV2, messages.MaxMessageSize).Healthcheck()

		var lastAnswer time.Time
		for i := 0; i < 3; i++ {
			at := <-writes
			if i == 0 {
				assert.Positive(t, at.Sub(start), "no send at connect")
				assert.LessOrEqual(t, at.Sub(start), period, "the first send is the next phase")
			}
			assert.Equal(t, phase.Milliseconds(), at.UnixMilli()%period.Milliseconds(), "send %d on the phase", i)
			frames := conn.frames()
			assert.Equal(t, stock, frames[len(frames)-1], "send %d is the stock frame", i)
			answer(ctx, p, hc, stock)
			lastAnswer = time.Now()
		}

		for !conn.isClosed() {
			select {
			case <-writes:
			case <-conn.closed:
			}
		}
		assert.LessOrEqual(t, time.Since(lastAnswer), 2*(period+20*time.Second), "silent aligned peer closed")
	})
}

// A peer without an accepted period keeps the stock 25 s interval and the stock frame.
func TestPeerStockHealthchecksOnInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		p, conn, hc, writes := alignedTestPeer(t, ctx, "stock-peer", 0)
		start := time.Now()
		stock := messages.NewEncoder(messages.ProtocolV2, messages.MaxMessageSize).Healthcheck()

		for i := 1; i <= 3; i++ {
			at := <-writes
			assert.Equal(t, time.Duration(i)*25*time.Second, at.Sub(start), "send %d on the stock interval", i)
			frames := conn.frames()
			assert.Equal(t, stock, frames[len(frames)-1], "send %d is the stock frame", i)
			answer(ctx, p, hc, stock)
		}
	})
}

// acceptAligned runs the relay accept flow for a client that asks for the period in its Auth
// message, and returns the response and the stored peer.
func acceptAligned(t *testing.T, relay *Relay, auth []byte, id messages.PeerID) ([]byte, *Peer) {
	t.Helper()
	conn := newScriptedConn()
	conn.deliver(t, auth)
	relay.Accept(conn)
	frames := conn.waitFrames(t, 1)
	item, ok := relay.store.Peer(id)
	require.True(t, ok, "the peer must be stored")
	return frames[0], item.(*Peer)
}

// responsePeriod returns the period entry of an AuthResponse.
func responsePeriod(t *testing.T, resp []byte) (uint16, bool) {
	t.Helper()
	ext, err := messages.UnmarshalAuthResponseExtension(resp)
	require.NoError(t, err)
	period, ok, err := messages.AlignedHeartbeatEntry(ext)
	require.NoError(t, err)
	return period, ok
}

// A bound-token client that asks for the period gets the clamped period in the v2 response and
// an aligned peer; one that asks for zero stays stock with the prepared response bytes.
func TestRelay_BoundTokenAlignedEntry(t *testing.T) {
	for raw, want := range map[uint16]time.Duration{0: 0, 1: 30 * time.Second, 60: 60 * time.Second, 65535: 300 * time.Second} {
		relay := newPeerAuthTestRelay(t, &recordingValidator{}, PeerAuthConfig{})
		peer := newBoundPeer(t)
		auth := peer.authMsg(t, peer.id, "relay-1.example.com", time.Now())
		auth = append(auth, messages.AppendAlignedHeartbeatEntry(nil, raw)...)

		resp, stored := acceptAligned(t, relay, auth, peer.id)
		assert.True(t, stored.Authenticated(), "asked %d s: the proof still authenticates", raw)
		assert.Equal(t, want, stored.alignedPeriod, "asked %d s: peer period", raw)
		addr, err := messages.UnmarshalAuthResponse(resp)
		require.NoError(t, err)
		assert.Equal(t, relay.instanceURL.String(), addr, "asked %d s: the URL is unchanged", raw)

		got, ok := responsePeriod(t, resp)
		if want == 0 {
			prepared, err := relay.preparedMsg.authResponse(messages.ProtocolV2)
			require.NoError(t, err)
			assert.Equal(t, prepared, resp, "a zero period gets the prepared response")
			assert.False(t, ok, "a zero period is not answered")
			continue
		}
		assert.True(t, ok, "asked %d s: the response carries the period", raw)
		assert.Equal(t, uint16(want/time.Second), got, "asked %d s: the clamped period is answered", raw)
	}
}

// The relay reads the entry on any auth path whose response can carry the answer: a legacy
// token in the v2 envelope gets it too. A v1 client cannot ask and keeps the v1 bytes.
func TestRelay_LegacyTokenAlignedEntry(t *testing.T) {
	relay := newTestRelay(t, &recordingValidator{})
	id := messages.HashID("legacy-envelope")
	auth, err := messages.MarshalAuthEnvelope(messages.ProtocolV2, id, []byte("token"), messages.AppendAlignedHeartbeatEntry(nil, 60))
	require.NoError(t, err)
	resp, stored := acceptAligned(t, relay, auth, id)
	got, ok := responsePeriod(t, resp)
	assert.True(t, ok, "a legacy envelope with the entry is answered")
	assert.Equal(t, uint16(60), got, "the asked period is answered")
	assert.Equal(t, 60*time.Second, stored.alignedPeriod, "the legacy envelope peer is aligned")

	conn, v1ID := acceptPeer(t, relay, "v1-client")
	want, err := messages.MarshalAuthResponse(relay.instanceURL.String())
	require.NoError(t, err)
	assert.Equal(t, want, conn.frames()[0], "a v1 client keeps the v1 response bytes")
	item, ok := relay.store.Peer(v1ID)
	require.True(t, ok, "the v1 peer must be stored")
	assert.Zero(t, item.(*Peer).alignedPeriod, "a v1 peer stays stock")
}

// A malformed aligned entry after the proof never refuses the client: it is authenticated,
// stays stock and gets the prepared response bytes.
func TestRelay_MalformedAlignedEntryStaysStock(t *testing.T) {
	for name, entry := range map[string][]byte{
		"one byte value":         {messages.ExtTypeAlignedHeartbeat, 0, 1, 60},
		"length beyond the area": {messages.ExtTypeAlignedHeartbeat, 0, 9, 0, 60},
		"short header":           {messages.ExtTypeAlignedHeartbeat, 0},
	} {
		relay := newPeerAuthTestRelay(t, &recordingValidator{}, PeerAuthConfig{})
		peer := newBoundPeer(t)
		auth := append(peer.authMsg(t, peer.id, "relay-1.example.com", time.Now()), entry...)

		resp, stored := acceptAligned(t, relay, auth, peer.id)
		prepared, err := relay.preparedMsg.authResponse(messages.ProtocolV2)
		require.NoError(t, err)
		assert.Equal(t, prepared, resp, "case %q: the prepared response", name)
		assert.True(t, stored.Authenticated(), "case %q: still authenticated", name)
		assert.Zero(t, stored.alignedPeriod, "case %q: stays stock", name)
	}
}

// The aligned gauge counts a peer accepted with a period while its connection lasts, and
// never a stock peer.
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
		// Eventually calls this from its own goroutine, where require cannot stop the test.
		assert.NoError(t, reader.Collect(context.Background(), rm))
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

	acceptPeer(t, relay, "stock-gauge-peer")
	assert.Equal(t, int64(0), gauge(), "a stock peer is not counted")

	conn := newScriptedConn()
	id := messages.HashID("gauge-peer")
	auth, err := messages.MarshalAuthEnvelope(messages.ProtocolV2, id, []byte("token"), messages.AppendAlignedHeartbeatEntry(nil, 60))
	require.NoError(t, err)
	conn.deliver(t, auth)
	relay.Accept(conn)
	conn.waitFrames(t, 1)
	require.Eventually(t, func() bool { return gauge() == 1 }, testWaitTimeout, 10*time.Millisecond,
		"the aligned peer is counted")

	require.NoError(t, conn.Close())
	assert.Eventually(t, func() bool { return gauge() == 0 }, testWaitTimeout, 10*time.Millisecond,
		"the ended peer is uncounted")
}
