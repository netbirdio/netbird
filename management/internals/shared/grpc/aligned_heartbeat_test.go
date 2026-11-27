package grpc

import (
	"context"
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"

	pb "github.com/golang/protobuf/proto" //nolint
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.uber.org/mock/gomock"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/keepalive"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

func TestAlignedHeartbeatAnswer(t *testing.T) {
	key := mustGenerateKey(t).PublicKey()
	withCap := []proto.PeerCapability{proto.PeerCapability_PeerCapabilityAlignedHeartbeat}
	withoutCap := []proto.PeerCapability{proto.PeerCapability_PeerCapabilitySourcePrefixes}

	cases := []struct {
		name    string
		caps    []proto.PeerCapability
		seconds uint32
		want    time.Duration
	}{
		{name: "empty request stays stock"},
		{name: "period without capability stays stock", caps: withoutCap, seconds: 60},
		{name: "capability without period stays stock", caps: withCap},
		{name: "release period", caps: withCap, seconds: 60, want: 60 * time.Second},
		{name: "short period clamped", caps: withCap, seconds: 1, want: 30 * time.Second},
		{name: "long period clamped", caps: withCap, seconds: 1000, want: 300 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := &proto.SyncRequest{Meta: &proto.PeerSystemMeta{Capabilities: tc.caps}}
			if tc.seconds > 0 {
				req.AlignedHeartbeat = &proto.AlignedHeartbeatRequest{PeriodSeconds: tc.seconds}
			}
			got := alignedHeartbeatAnswer(req, key)
			if tc.want == 0 {
				assert.Nil(t, got, "no answer expected")
				return
			}
			require.NotNil(t, got, "capability and period must turn the heartbeat on")
			assert.Equal(t, tc.want, got.period, "period Management sends on")
			assert.Equal(t, alignedhb.Phase(messages.HashID(key.String()), tc.want), got.phase,
				"Management must tick on the phase Signal and relay compute for the same peer")
			assert.True(t, pb.Equal(&proto.AlignedHeartbeatConfig{Enabled: true, PeriodSeconds: uint32(tc.want / time.Second)}, got.config()),
				"confirmed config")
		})
	}
}

// sentMessage is a message the handler sent and the time it sent it.
type sentMessage struct {
	msg *proto.EncryptedMessage
	at  time.Time
}

type chanSyncSender struct {
	ctx  context.Context
	sent chan sentMessage
}

func (c *chanSyncSender) Send(m *proto.EncryptedMessage) error {
	c.sent <- sentMessage{msg: m, at: time.Now()}
	return nil
}

func (c *chanSyncSender) Context() context.Context { return c.ctx }

// handlerRun is a running HandleUpdates of one stream.
type handlerRun struct {
	srv    *chanSyncSender
	peer   wgtypes.Key
	server wgtypes.Key
	stop   func()
}

// startHandler runs HandleUpdates for a stream with aligned (nil is stock)
// on the stream context ctx. setup may adjust the handler before it runs.
func startHandler(t *testing.T, ctx context.Context, aligned *alignedHeartbeat, setup func(*PeerUpdateHandler)) *handlerRun {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	run := &handlerRun{
		srv:    &chanSyncSender{ctx: ctx, sent: make(chan sentMessage, 16)},
		peer:   mustGenerateKey(t),
		server: mustGenerateKey(t),
	}
	secretsManager := NewMockSecretsManager(gomock.NewController(t))
	secretsManager.EXPECT().GetWGKey().AnyTimes().Return(run.server, nil)
	pu := &PeerUpdateHandler{
		peerKey:        run.peer.PublicKey(),
		updates:        make(chan *network_map.UpdateMessage),
		secretsManager: secretsManager,
		encrypter:      encryption.DefaultEncrypter{},
		debouncer:      NewUpdateDebouncer(time.Second),
		srv:            run.srv,
		cleanupFunc:    func() {},
	}
	if setup != nil {
		setup(pu)
	}
	pu.WithAlignedHeartbeat(aligned)

	done := make(chan error, 1)
	go func() { done <- pu.HandleUpdates(ctx) }()
	stopped := false
	run.stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		if err := <-done; err != nil {
			assert.True(t, errors.Is(err, context.Canceled), "handler ended with %v", err)
		}
	}
	t.Cleanup(run.stop)
	return run
}

// An aligned stream gets one heartbeat per period on its phase, carrying
// only the heartbeat marker.
func TestHandleUpdates_AlignedHeartbeat(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		aligned := &alignedHeartbeat{period: time.Minute, phase: 1234 * time.Millisecond}
		run := startHandler(t, context.Background(), aligned, nil)

		time.Sleep(3 * aligned.period)
		synctest.Wait()
		run.stop()

		require.Len(t, run.srv.sent, 3, "one heartbeat per period")
		for i := 0; i < 3; i++ {
			sent := <-run.srv.sent
			assert.Equal(t, aligned.phase.Milliseconds(), sent.at.UnixMilli()%aligned.period.Milliseconds(),
				"heartbeat %d on the phase", i)
			resp := &proto.SyncResponse{}
			require.NoError(t, encryption.DecryptMessage(run.server.PublicKey(), run.peer, sent.msg.Body, resp))
			assert.True(t, pb.Equal(&proto.SyncResponse{Heartbeat: &proto.Heartbeat{}}, resp),
				"heartbeat %d must carry only the heartbeat marker, got %v", i, resp)
		}
	})
}

// A stream without an aligned answer gets no heartbeat.
func TestHandleUpdates_NoHeartbeatWithoutAnswer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		run := startHandler(t, context.Background(), nil, nil)

		time.Sleep(2 * time.Minute)
		synctest.Wait()
		run.stop()

		assert.Empty(t, run.srv.sent, "a stock stream must not get heartbeats over two periods")
	})
}

// The aligned gauge counts aligned streams while they run and returns to
// zero when they end. Stock streams are never counted.
func TestHandleUpdates_AlignedGauge(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	grpcMetrics, err := telemetry.NewGRPCMetrics(context.Background(), provider.Meter("test"))
	require.NoError(t, err)
	appMetrics := &telemetry.MockAppMetrics{GRPCMetricsFunc: func() *telemetry.GRPCMetrics { return grpcMetrics }}
	withMetrics := func(pu *PeerUpdateHandler) { pu.WithMetrics(appMetrics) }

	gauge := func() int64 {
		rm := &metricdata.ResourceMetrics{}
		require.NoError(t, reader.Collect(context.Background(), rm))
		var total int64
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				if m.Name != "management.grpc.aligned.streams" {
					continue
				}
				sum, ok := m.Data.(metricdata.Sum[int64])
				require.True(t, ok, "aligned streams metric type %T", m.Data)
				for _, dp := range sum.DataPoints {
					total += dp.Value
				}
			}
		}
		return total
	}

	stock := startHandler(t, context.Background(), nil, withMetrics)
	assert.Never(t, func() bool { return gauge() != 0 }, 200*time.Millisecond, 10*time.Millisecond, "stock stream must not be counted")
	stock.stop()

	aligned := startHandler(t, context.Background(), &alignedHeartbeat{period: time.Minute, phase: time.Second}, withMetrics)
	assert.Eventually(t, func() bool { return gauge() == 1 }, 2*time.Second, 10*time.Millisecond, "aligned stream counted")
	aligned.stop()
	assert.Equal(t, int64(0), gauge(), "ended aligned stream uncounted")
}

// acceptedConn returns the server end of a loopback TCP connection.
func acceptedConn(t *testing.T) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	srv, err := ln.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

// idleOf returns the keepalive idle of c, or -1 when it cannot be read. It
// is safe inside assert.Eventually callbacks.
func idleOf(c net.Conn) time.Duration {
	idle, err := keepalive.Idle(c)
	if err != nil {
		return -1
	}
	return idle
}

// An aligned Sync stream sets the keepalive of its connection to twice the
// period and leaves it there when it ends. A stock stream leaves the
// connection as accepted.
func TestHandleUpdates_AlignedKeepAlive(t *testing.T) {
	if _, err := keepalive.Idle(nil); errors.Is(err, errors.ErrUnsupported) {
		t.Skip(err)
	}

	conn := acceptedConn(t)
	aligned := startHandler(t, keepalive.ConnContext(context.Background(), conn),
		&alignedHeartbeat{period: time.Minute, phase: time.Second}, nil)
	assert.Eventually(t, func() bool { return idleOf(conn) == 2*time.Minute }, 2*time.Second, 10*time.Millisecond,
		"aligned stream: idle twice the period")
	aligned.stop()
	assert.Equal(t, 2*time.Minute, idleOf(conn), "the ended stream leaves the aligned keepalive, never restored")

	stockConn := acceptedConn(t)
	accepted := idleOf(stockConn)
	require.Positive(t, accepted, "stock idle readable")
	startHandler(t, keepalive.ConnContext(context.Background(), stockConn), nil, nil)
	assert.Never(t, func() bool { return idleOf(stockConn) != accepted }, 200*time.Millisecond, 10*time.Millisecond,
		"stock stream must not touch the keepalive")
}
