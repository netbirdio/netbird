package grpc

import (
	"context"
	"errors"
	"testing"
	"time"

	pb "github.com/golang/protobuf/proto" //nolint
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/hbmetrics/hbmetricstest"
	"github.com/netbirdio/netbird/shared/alignedhb/phasesig"
	"github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/relay/messages"
	"github.com/netbirdio/netbird/util"
)

func alignedSyncRequest(caps []proto.PeerCapability, periodSeconds uint32) *proto.SyncRequest {
	req := &proto.SyncRequest{Meta: &proto.PeerSystemMeta{Capabilities: caps}}
	if periodSeconds > 0 {
		req.AlignedHeartbeat = &proto.AlignedHeartbeatRequest{PeriodSeconds: periodSeconds}
	}
	return req
}

func TestAlignedHeartbeatAnswer(t *testing.T) {
	key := mustGenerateKey(t).PublicKey()
	withCap := []proto.PeerCapability{proto.PeerCapability_PeerCapabilitySourcePrefixes, proto.PeerCapability_PeerCapabilityAlignedHeartbeat}
	withoutCap := []proto.PeerCapability{proto.PeerCapability_PeerCapabilitySourcePrefixes}
	signer, err := phasesig.NewSigner("relay-secret")
	require.NoError(t, err)
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

	assert.Nil(t, alignedHeartbeatAnswer(&proto.SyncRequest{}, key, signer, alignedhb.PeriodLimits{}, now), "an empty request must stay stock")
	assert.Nil(t, alignedHeartbeatAnswer(alignedSyncRequest(withoutCap, 60), key, signer, alignedhb.PeriodLimits{}, now), "a period without the capability must stay stock")
	assert.Nil(t, alignedHeartbeatAnswer(alignedSyncRequest(withCap, 0), key, signer, alignedhb.PeriodLimits{}, now), "the capability without a period must stay stock")
	assert.Nil(t, alignedHeartbeatAnswer(alignedSyncRequest(withCap, 60), key, nil, alignedhb.PeriodLimits{}, now), "no signer must stay stock")

	got := alignedHeartbeatAnswer(alignedSyncRequest(withCap, 60), key, signer, alignedhb.PeriodLimits{}, now)
	require.NotNil(t, got, "capability and period must turn the heartbeat on")
	assert.Equal(t, 60*time.Second, got.answer.Period, "period")
	assert.Equal(t, got.signed.Phase, got.answer.Phase, "Management must tick on the phase it signs")
	assert.Equal(t, phasesig.Day(now), got.signed.Day, "day of the server clock")

	verifier, err := phasesig.NewVerifier("relay-secret")
	require.NoError(t, err)
	assert.NoError(t, verifier.Verify(messages.HashID(key.String()), 60*time.Second, got.signed, now),
		"Signal and relay must accept the signed phase for the peer")
}

func TestAlignedHeartbeatAnswer_SameAcrossInstances(t *testing.T) {
	// Two Management instances, or one before and after a restart, share the
	// relay secret and must give a peer the same phase on the same day.
	key := mustGenerateKey(t).PublicKey()
	req := alignedSyncRequest([]proto.PeerCapability{proto.PeerCapability_PeerCapabilityAlignedHeartbeat}, 60)
	cfg := &nbconfig.Relay{Secret: "relay-secret"}
	first, second := newPhaseSigner(cfg), newPhaseSigner(cfg)
	require.NotNil(t, first)
	require.NotNil(t, second)

	morning := time.Date(2026, 11, 13, 6, 0, 0, 0, time.UTC)
	a := alignedHeartbeatAnswer(req, key, first, alignedhb.PeriodLimits{}, morning)
	b := alignedHeartbeatAnswer(req, key, second, alignedhb.PeriodLimits{}, morning.Add(10*time.Hour))
	require.NotNil(t, a)
	require.NotNil(t, b)
	assert.Equal(t, a.answer, b.answer, "same schedule on both instances")
	assert.Equal(t, a.signed, b.signed, "same signed phase on both instances")

	assert.Nil(t, newPhaseSigner(&nbconfig.Relay{}), "no secret, no signer")
	assert.Nil(t, newPhaseSigner(nil), "no relay config, no signer")
}

func TestAlignedHeartbeatAnswer_PeersSpread(t *testing.T) {
	signer, err := phasesig.NewSigner("relay-secret")
	require.NoError(t, err)
	req := alignedSyncRequest([]proto.PeerCapability{proto.PeerCapability_PeerCapabilityAlignedHeartbeat}, 60)
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

	const peers = 600
	seconds := make(map[int64]int)
	for i := 0; i < peers; i++ {
		got := alignedHeartbeatAnswer(req, mustGenerateKey(t).PublicKey(), signer, alignedhb.PeriodLimits{}, now)
		require.NotNil(t, got)
		seconds[int64(got.answer.Phase/time.Second)]++
	}
	// 600 peers over 60 seconds of the period: expect about 10 per second.
	assert.Greater(t, len(seconds), 50, "peers must land on most seconds of the period")
	for s, n := range seconds {
		assert.Less(t, n, 30, "second %d holds %d peers", s, n)
	}
}

func TestSetAlignedHeartbeatConfig(t *testing.T) {
	aligned := &alignedHeartbeat{
		answer: alignedhb.Answer{Period: 60 * time.Second, Phase: 1234 * time.Millisecond},
		signed: alignedhb.SignedPhase{Phase: 1234 * time.Millisecond, Day: 20405, Signature: []byte{1, 2, 3}},
	}
	shared := &proto.PeerConfig{Address: "100.64.0.1/16"}
	legacy := &proto.SyncResponse{PeerConfig: shared, NetworkMap: &proto.NetworkMap{PeerConfig: shared}}
	setAlignedHeartbeatConfig(legacy, aligned)
	want := &proto.AlignedHeartbeatConfig{Enabled: true, PeriodSeconds: 60, PhaseMillis: 1234, PhaseSignature: []byte{1, 2, 3}, PhaseDay: 20405}
	assert.True(t, pb.Equal(want, legacy.GetPeerConfig().GetAlignedHeartbeat()), "top level peer config")
	assert.True(t, pb.Equal(want, legacy.GetNetworkMap().GetPeerConfig().GetAlignedHeartbeat()), "network map peer config")

	envelope := &proto.SyncResponse{PeerConfig: &proto.PeerConfig{}}
	setAlignedHeartbeatConfig(envelope, &alignedHeartbeat{answer: alignedhb.Answer{Period: 30 * time.Second}})
	assert.True(t, envelope.GetPeerConfig().GetAlignedHeartbeat().GetEnabled(), "envelope response carries it at the top level")

	stock := &proto.SyncResponse{PeerConfig: &proto.PeerConfig{}}
	setAlignedHeartbeatConfig(stock, nil)
	assert.Nil(t, stock.GetPeerConfig().GetAlignedHeartbeat(), "no answer must leave the peer config unchanged")
}

type chanSyncSender struct {
	ctx  context.Context
	sent chan *proto.EncryptedMessage
}

func (c *chanSyncSender) Send(m *proto.EncryptedMessage) error {
	c.sent <- m
	return nil
}

func (c *chanSyncSender) Context() context.Context { return c.ctx }

func newHeartbeatTestHandler(t *testing.T, srv syncSender) (*PeerUpdateHandler, *MockSecretsManager) {
	t.Helper()
	ctrl := gomock.NewController(t)
	secretsManager := NewMockSecretsManager(ctrl)
	return &PeerUpdateHandler{
		peerKey:        mustGenerateKey(t).PublicKey(),
		updates:        make(chan *network_map.UpdateMessage),
		secretsManager: secretsManager,
		encrypter:      encryption.DefaultEncrypter{},
		debouncer:      NewUpdateDebouncer(time.Second),
		srv:            srv,
		cleanupFunc:    func() {},
	}, secretsManager
}

func TestHandleUpdates_AlignedHeartbeatOnPhase(t *testing.T) {
	srvCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &chanSyncSender{ctx: srvCtx, sent: make(chan *proto.EncryptedMessage, 4)}
	pu, secretsManager := newHeartbeatTestHandler(t, srv)
	peerPriv := mustGenerateKey(t)
	pu.peerKey = peerPriv.PublicKey()
	srvKey := mustGenerateKey(t)
	secretsManager.EXPECT().GetWGKey().AnyTimes().Return(srvKey, nil)

	aligned := &alignedHeartbeat{
		answer: alignedhb.Answer{Period: time.Second, Phase: 300 * time.Millisecond},
		signed: alignedhb.SignedPhase{Phase: 300 * time.Millisecond, Day: phasesig.Day(time.Now())},
	}
	pu.WithAlignedHeartbeat(aligned, nil)

	done := make(chan error, 1)
	go func() { done <- pu.HandleUpdates(srvCtx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			assert.True(t, errors.Is(err, context.Canceled), "handler ended with %v", err)
		}
	}()

	for i := 0; i < 2; i++ {
		select {
		case msg := <-srv.sent:
			off := time.Now().UnixMilli() % 1000
			assert.True(t, off >= 300 && off < 400, "heartbeat %d at ms %d of the period, want 300", i, off)
			resp := &proto.SyncResponse{Version: 99}
			require.NoError(t, encryption.DecryptMessage(srvKey.PublicKey(), peerPriv, msg.Body, resp))
			want := &proto.SyncResponse{Heartbeat: &proto.Heartbeat{}}
			assert.True(t, pb.Equal(want, resp), "heartbeat must carry only the heartbeat marker, got %v", resp)
		case <-time.After(3 * time.Second):
			t.Fatalf("no heartbeat %d within 3s", i)
		}
	}
}

func TestHandleUpdates_NoHeartbeatWithoutAnswer(t *testing.T) {
	srvCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &chanSyncSender{ctx: srvCtx, sent: make(chan *proto.EncryptedMessage, 4)}
	pu, _ := newHeartbeatTestHandler(t, srv)
	pu.WithAlignedHeartbeat(nil, nil)

	done := make(chan error, 1)
	go func() { done <- pu.HandleUpdates(srvCtx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			assert.True(t, errors.Is(err, context.Canceled), "handler ended with %v", err)
		}
	}()

	select {
	case <-srv.sent:
		t.Fatal("a stock stream must not get heartbeats")
	case <-time.After(1500 * time.Millisecond):
	}
}

// scriptedTicker replaces alignedhb.Ticker: it records the schedule of every
// tick the handler starts and fires only when the test says so.
type scriptedTicker struct {
	started chan alignedhb.Answer
	tick    chan time.Time
}

func newScriptedTicker() *scriptedTicker {
	return &scriptedTicker{started: make(chan alignedhb.Answer, 4), tick: make(chan time.Time)}
}

func (s *scriptedTicker) newTicker(_ context.Context, period, phase time.Duration, _ func() time.Time) <-chan time.Time {
	s.started <- alignedhb.Answer{Period: period, Phase: phase}
	return s.tick
}

func (s *scriptedTicker) waitStart(t *testing.T) alignedhb.Answer {
	t.Helper()
	select {
	case a := <-s.started:
		return a
	case <-time.After(3 * time.Second):
		t.Fatal("no tick started within 3s")
		return alignedhb.Answer{}
	}
}

func (s *scriptedTicker) fire(t *testing.T) {
	t.Helper()
	select {
	case s.tick <- time.Now():
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not take the tick within 3s")
	}
}

// The first tick after the day change signs the phase of the new day, sends it
// in that heartbeat and moves the tick to it. The tick source is scripted, so
// the test checks which schedule the handler ticks on without depending on
// scheduler delay. TestHandleUpdates_AlignedHeartbeatOnPhase and the
// alignedhb.Ticker tests cover that a schedule fires on its phase.
func TestHandleUpdates_NewDayMovesPhase(t *testing.T) {
	srvCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &chanSyncSender{ctx: srvCtx, sent: make(chan *proto.EncryptedMessage, 8)}
	pu, secretsManager := newHeartbeatTestHandler(t, srv)
	peerPriv := mustGenerateKey(t)
	pu.peerKey = peerPriv.PublicKey()
	srvKey := mustGenerateKey(t)
	secretsManager.EXPECT().GetWGKey().AnyTimes().Return(srvKey, nil)
	ticker := newScriptedTicker()
	pu.newTicker = ticker.newTicker

	signer, err := phasesig.NewSigner("relay-secret")
	require.NoError(t, err)
	peer := messages.HashID(pu.peerKey.String())
	today := phasesig.Day(time.Now())
	newPhase := signer.Phase(peer, time.Minute, today)
	oldPhase := (newPhase + 30*time.Second) % time.Minute
	// Signed yesterday: the stream opened before the day change.
	pu.WithAlignedHeartbeat(&alignedHeartbeat{
		answer: alignedhb.Answer{Period: time.Minute, Phase: oldPhase},
		signed: alignedhb.SignedPhase{Phase: oldPhase, Day: today - 1},
	}, signer)

	done := make(chan error, 1)
	go func() { done <- pu.HandleUpdates(srvCtx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			assert.True(t, errors.Is(err, context.Canceled), "handler ended with %v", err)
		}
	}()

	receive := func(i int) *proto.SyncResponse {
		t.Helper()
		select {
		case msg := <-srv.sent:
			resp := &proto.SyncResponse{}
			require.NoError(t, encryption.DecryptMessage(srvKey.PublicKey(), peerPriv, msg.Body, resp))
			require.NotNil(t, resp.GetHeartbeat(), "heartbeat %d", i)
			return resp
		case <-time.After(3 * time.Second):
			t.Fatalf("no heartbeat %d within 3s", i)
			return nil
		}
	}

	assert.Equal(t, alignedhb.Answer{Period: time.Minute, Phase: oldPhase}, ticker.waitStart(t),
		"the first tick still comes on the old phase")
	ticker.fire(t)
	first := receive(0)
	cfg := first.GetHeartbeat().GetConfig()
	require.NotNil(t, cfg, "the first heartbeat of the new day carries the new phase")
	assert.Equal(t, uint32(newPhase.Milliseconds()), cfg.GetPhaseMillis(), "phase of the new day")
	assert.Equal(t, uint32(60), cfg.GetPeriodSeconds(), "period stays")
	assert.Equal(t, today, cfg.GetPhaseDay(), "day")
	verifier, err := phasesig.NewVerifier("relay-secret")
	require.NoError(t, err)
	assert.NoError(t, verifier.Verify(peer, time.Minute, alignedhb.SignedPhase{
		Phase: newPhase, Day: cfg.GetPhaseDay(), Signature: cfg.GetPhaseSignature(),
	}, time.Now()), "Signal and relay must accept the new phase")

	assert.Equal(t, alignedhb.Answer{Period: time.Minute, Phase: newPhase}, ticker.waitStart(t),
		"after the new day heartbeat the tick moves to the new phase")
	for i := 1; i <= 2; i++ {
		ticker.fire(t)
		resp := receive(i)
		assert.Nil(t, resp.GetHeartbeat().GetConfig(), "heartbeat %d carries no config", i)
	}
	select {
	case a := <-ticker.started:
		t.Fatalf("the tick moved again to %+v on the same day", a)
	default:
	}
}

// A client that never sends the capability gets no heartbeat on its Sync
// stream, whatever period it sends. Limits down to one second make a wrongly
// started heartbeat show within the test.
func TestHandleUpdates_StockClientGetsNoHeartbeat(t *testing.T) {
	signer, err := phasesig.NewSigner("relay-secret")
	require.NoError(t, err)
	limits := alignedhb.PeriodLimits{Min: time.Second, Max: alignedhb.MaxPeriod}
	withCap := []proto.PeerCapability{proto.PeerCapability_PeerCapabilityAlignedHeartbeat}
	stockCaps := []proto.PeerCapability{proto.PeerCapability_PeerCapabilitySourcePrefixes}

	cases := []struct {
		name string
		req  *proto.SyncRequest
		want bool
	}{
		{"old client without capabilities", &proto.SyncRequest{Meta: &proto.PeerSystemMeta{}}, false},
		{"desktop client with other capabilities", alignedSyncRequest(stockCaps, 0), false},
		{"period without the capability", alignedSyncRequest(stockCaps, 1), false},
		{"capability without a period", alignedSyncRequest(withCap, 0), false},
		{"capability and period", alignedSyncRequest(withCap, 1), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srvCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			srv := &chanSyncSender{ctx: srvCtx, sent: make(chan *proto.EncryptedMessage, 4)}
			pu, secretsManager := newHeartbeatTestHandler(t, srv)
			peerPriv := mustGenerateKey(t)
			pu.peerKey = peerPriv.PublicKey()
			srvKey := mustGenerateKey(t)
			secretsManager.EXPECT().GetWGKey().AnyTimes().Return(srvKey, nil)

			aligned := alignedHeartbeatAnswer(tc.req, pu.peerKey, signer, limits, time.Now())
			assert.Equal(t, tc.want, aligned != nil, "aligned heartbeat answer")
			first := &proto.SyncResponse{PeerConfig: &proto.PeerConfig{Address: "100.64.0.1/16"}}
			setAlignedHeartbeatConfig(first, aligned)
			assert.Equal(t, tc.want, first.GetPeerConfig().GetAlignedHeartbeat() != nil, "peer config of the first response")
			pu.WithAlignedHeartbeat(aligned, signer)

			done := make(chan error, 1)
			go func() { done <- pu.HandleUpdates(srvCtx) }()
			defer func() {
				cancel()
				if err := <-done; err != nil {
					assert.True(t, errors.Is(err, context.Canceled), "handler ended with %v", err)
				}
			}()

			select {
			case msg := <-srv.sent:
				require.True(t, tc.want, "a stock stream must not get heartbeats")
				resp := &proto.SyncResponse{}
				require.NoError(t, encryption.DecryptMessage(srvKey.PublicKey(), peerPriv, msg.Body, resp))
				assert.NotNil(t, resp.GetHeartbeat(), "the aligned stream gets a heartbeat")
			case <-time.After(2500 * time.Millisecond):
				assert.False(t, tc.want, "the aligned stream must get a heartbeat within 2.5s")
			}
		})
	}
}

func TestAlignedHeartbeatResign(t *testing.T) {
	signer, err := phasesig.NewSigner("relay-secret")
	require.NoError(t, err)
	key := mustGenerateKey(t).PublicKey()
	now := time.Date(2026, 11, 13, 0, 0, 1, 0, time.UTC)
	today := alignedHeartbeatAnswer(alignedSyncRequest([]proto.PeerCapability{proto.PeerCapability_PeerCapabilityAlignedHeartbeat}, 60), key, signer, alignedhb.PeriodLimits{}, now)
	require.NotNil(t, today)

	assert.Nil(t, today.resign(signer, key, now.Add(time.Hour)), "same day: no new phase")
	assert.Nil(t, today.resign(nil, key, now.Add(24*time.Hour)), "no signer: no new phase")
	var none *alignedHeartbeat
	assert.Nil(t, none.resign(signer, key, now.Add(24*time.Hour)), "stock stream: no new phase")

	next := today.resign(signer, key, now.Add(24*time.Hour))
	require.NotNil(t, next, "next day: new phase")
	assert.Equal(t, today.signed.Day+1, next.signed.Day, "day")
	assert.Equal(t, today.answer.Period, next.answer.Period, "period stays")
	assert.Equal(t, next.signed.Phase, next.answer.Phase, "Management ticks on the new signed phase")
}

func TestAlignedHeartbeatAnswer_ClampsPeriod(t *testing.T) {
	key := mustGenerateKey(t).PublicKey()
	caps := []proto.PeerCapability{proto.PeerCapability_PeerCapabilityAlignedHeartbeat}
	signer, err := phasesig.NewSigner("relay-secret")
	require.NoError(t, err)
	verifier, err := phasesig.NewVerifier("relay-secret")
	require.NoError(t, err)
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

	for requested, want := range map[uint32]time.Duration{
		1:    30 * time.Second,
		1000: 300 * time.Second,
		60:   60 * time.Second,
	} {
		got := alignedHeartbeatAnswer(alignedSyncRequest(caps, requested), key, signer, alignedhb.DefaultPeriodLimits(), now)
		require.NotNil(t, got, "requested %d s", requested)
		assert.Equal(t, want, got.answer.Period, "requested %d s: period Management sends on", requested)

		// The peer config confirms the period Management ticks on, and the
		// signature covers it, so Signal and relay verify the same period.
		cfg := got.config()
		assert.Equal(t, uint32(want/time.Second), cfg.GetPeriodSeconds(), "requested %d s: confirmed period", requested)
		assert.True(t, alignedhb.ValidPhase(got.answer.Phase, want), "requested %d s: phase inside the clamped period", requested)
		assert.NoError(t, verifier.Verify(messages.HashID(key.String()), want, got.signed, now),
			"requested %d s: phase signed for the clamped period", requested)
	}
}

func TestNewPeriodLimits(t *testing.T) {
	d := func(v time.Duration) util.Duration { return util.Duration{Duration: v} }
	def := alignedhb.DefaultPeriodLimits()

	for name, tc := range map[string]struct {
		cfg  nbconfig.AlignedHeartbeat
		want alignedhb.PeriodLimits
	}{
		"unset":    {cfg: nbconfig.AlignedHeartbeat{}, want: def},
		"only min": {cfg: nbconfig.AlignedHeartbeat{MinPeriod: d(45 * time.Second)}, want: alignedhb.PeriodLimits{Min: 45 * time.Second, Max: def.Max}},
		"only max": {cfg: nbconfig.AlignedHeartbeat{MaxPeriod: d(120 * time.Second)}, want: alignedhb.PeriodLimits{Min: def.Min, Max: 120 * time.Second}},
		"both":     {cfg: nbconfig.AlignedHeartbeat{MinPeriod: d(45 * time.Second), MaxPeriod: d(120 * time.Second)}, want: alignedhb.PeriodLimits{Min: 45 * time.Second, Max: 120 * time.Second}},
	} {
		got, err := newPeriodLimits(tc.cfg)
		require.NoError(t, err, name)
		assert.Equal(t, tc.want, got, "case %s", name)
	}

	// Config may only narrow the default range.
	for name, cfg := range map[string]nbconfig.AlignedHeartbeat{
		"min below 30s":  {MinPeriod: d(10 * time.Second)},
		"max above 300s": {MaxPeriod: d(600 * time.Second)},
		"both outside":   {MinPeriod: d(10 * time.Second), MaxPeriod: d(600 * time.Second)},
		"max below min":  {MinPeriod: d(200 * time.Second), MaxPeriod: d(100 * time.Second)},
		"fractional":     {MinPeriod: d(45500 * time.Millisecond)},
	} {
		_, err := newPeriodLimits(cfg)
		assert.Error(t, err, "case %s must be rejected", name)
	}
}

// Management refuses to start with limits outside the default range. The
// check runs before any dependency is touched, so none is needed here.
func TestNewServerRejectsBadPeriodLimits(t *testing.T) {
	cfg := &nbconfig.Config{AlignedHeartbeat: nbconfig.AlignedHeartbeat{
		MinPeriod: util.Duration{Duration: 10 * time.Second},
		MaxPeriod: util.Duration{Duration: 600 * time.Second},
	}}
	srv, err := NewServer(cfg, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	assert.Error(t, err, "a 10s min and a 600s max must be rejected")
	assert.Nil(t, srv, "no server on rejected limits")
}

// Every heartbeat sent is counted in the gRPC metrics.
func TestHandleUpdates_HeartbeatMetric(t *testing.T) {
	srvCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &chanSyncSender{ctx: srvCtx, sent: make(chan *proto.EncryptedMessage, 4)}
	pu, secretsManager := newHeartbeatTestHandler(t, srv)
	secretsManager.EXPECT().GetWGKey().AnyTimes().Return(mustGenerateKey(t), nil)
	ticker := newScriptedTicker()
	pu.newTicker = ticker.newTicker

	meter, reader := hbmetricstest.NewMeter()
	grpcMetrics, err := telemetry.NewGRPCMetrics(srvCtx, meter)
	require.NoError(t, err)
	pu.WithMetrics(&telemetry.MockAppMetrics{GRPCMetricsFunc: func() *telemetry.GRPCMetrics { return grpcMetrics }})
	pu.WithAlignedHeartbeat(&alignedHeartbeat{
		answer: alignedhb.Answer{Period: time.Minute, Phase: time.Second},
		signed: alignedhb.SignedPhase{Phase: time.Second, Day: phasesig.Day(time.Now())},
	}, nil)

	done := make(chan error, 1)
	go func() { done <- pu.HandleUpdates(srvCtx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			assert.True(t, errors.Is(err, context.Canceled), "handler ended with %v", err)
		}
	}()

	ticker.waitStart(t)
	for i := 0; i < 2; i++ {
		ticker.fire(t)
		select {
		case <-srv.sent:
		case <-time.After(3 * time.Second):
			t.Fatalf("no heartbeat %d within 3s", i)
		}
	}
	require.Eventually(t, func() bool {
		return hbmetricstest.Counts(t, reader)["management.grpc.aligned_heartbeat_sent_total"] == 2
	}, time.Second, 10*time.Millisecond, "two heartbeats counted")
}
