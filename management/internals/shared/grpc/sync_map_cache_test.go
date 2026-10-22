package grpc

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	testcontainersredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/internals/shared/syncmapcache"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func TestClientKeepsStateOnConfigOnlySync(t *testing.T) {
	cases := map[string]bool{
		"0.72.2":      false,
		"0.72.3":      true,
		"0.80.0":      true,
		"development": true,
		"":            false,
		"garbage":     false,
	}
	for v, want := range cases {
		assert.Equal(t, want, clientKeepsStateOnConfigOnlySync(v), "client version %q", v)
	}
}

func TestDeliveredSerial(t *testing.T) {
	serial, ok := deliveredSerial(&proto.SyncResponse{NetworkMap: &proto.NetworkMap{Serial: 7}})
	assert.True(t, ok, "a legacy map is a delivered map")
	assert.Equal(t, uint64(7), serial, "legacy serial")

	serial, ok = deliveredSerial(&proto.SyncResponse{NetworkMapEnvelope: &proto.NetworkMapEnvelope{
		Payload: &proto.NetworkMapEnvelope_Full{Full: &proto.NetworkMapComponentsFull{Network: &proto.AccountNetwork{Serial: 9}}},
	}})
	assert.True(t, ok, "a full envelope is a delivered map")
	assert.Equal(t, uint64(9), serial, "the client applies the account network serial of the envelope")

	_, ok = deliveredSerial(&proto.SyncResponse{NetbirdConfig: &proto.NetbirdConfig{}})
	assert.False(t, ok, "a config-only response delivers no map")

	_, ok = deliveredSerial(&proto.SyncResponse{NetworkMapEnvelope: &proto.NetworkMapEnvelope{}})
	assert.False(t, ok, "an envelope without a full payload delivers no map")
}

func TestSyncMapGeneration(t *testing.T) {
	v1, v2 := 1, 2
	base := &nbconfig.Config{HighestSupportedSyncMessageVersion: &v1}

	assert.Equal(t, SyncMapGeneration(base, "netbird.cloud"), SyncMapGeneration(base, "netbird.cloud"), "the same build and config must keep the generation")
	assert.NotEqual(t, SyncMapGeneration(base, "netbird.cloud"), SyncMapGeneration(base, "netbird.selfhosted"), "the DNS domain shapes every map")
	assert.NotEqual(t, SyncMapGeneration(base, "netbird.cloud"),
		SyncMapGeneration(&nbconfig.Config{HighestSupportedSyncMessageVersion: &v2}, "netbird.cloud"),
		"the sync message version decides the map's wire format")
	assert.NotEqual(t, SyncMapGeneration(base, "netbird.cloud"),
		SyncMapGeneration(&nbconfig.Config{HighestSupportedSyncMessageVersion: &v1, PerAccountHighestSupportedSyncMessageVersion: map[string]int{"acc": 2}}, "netbird.cloud"),
		"per-account sync message versions decide the map's wire format")
}

func TestToConfigOnlySyncResponse(t *testing.T) {
	cfg := &nbconfig.Config{
		Stuns:  []*nbconfig.Host{{Proto: nbconfig.UDP, URI: "stun:stun.example.com:3478"}},
		Relay:  &nbconfig.Relay{Addresses: []string{"rels://relay.example.com:443"}},
		Signal: &nbconfig.Host{Proto: nbconfig.HTTP, URI: "signal.example.com:10000"},
	}
	lastLogin := time.Now().UTC()
	peer := &nmdata.Peer{ID: "peer", UserID: "user", LoginExpirationEnabled: true, LastLogin: &lastLogin}
	settings := &nmdata.AccountSettingsInfo{PeerLoginExpirationEnabled: true, PeerLoginExpiration: time.Hour}
	relayToken := &Token{Payload: "payload", Signature: "signature"}

	resp := toConfigOnlySyncResponse(cfg, peer, nil, relayToken, settings, nil, nil)

	assert.Nil(t, resp.GetNetworkMap(), "a config-only response carries no map")
	assert.Nil(t, resp.GetNetworkMapEnvelope(), "a config-only response carries no envelope")
	assert.Nil(t, resp.GetPeerConfig(), "a peer config without auto-update settings would change the client's updater mode")
	assert.Nil(t, resp.GetChecks(), "posture checks ride with the map")
	assert.Zero(t, resp.GetVersion(), "the response must be readable as config-only by every client")
	require.NotNil(t, resp.GetNetbirdConfig(), "connection config")
	require.NotNil(t, resp.GetNetbirdConfig().GetRelay(), "a config without its relay section makes clients drop their relays")
	assert.Equal(t, "payload", resp.GetNetbirdConfig().GetRelay().GetTokenPayload(), "fresh relay credentials")
	assert.NotEmpty(t, resp.GetNetbirdConfig().GetStuns(), "STUN servers")
	require.NotNil(t, resp.GetSessionExpiresAt(), "the session deadline is refreshed on every Sync")
	assert.Equal(t, lastLogin.Add(time.Hour).Unix(), resp.GetSessionExpiresAt().GetSeconds(), "session deadline")
}

// recordedPushes collects the pushes of a resync scheduler under test.
type recordedPushes struct {
	mu    sync.Mutex
	calls map[string][]string
	fail  int
}

func (p *recordedPushes) push(_ context.Context, accountID string, peerIDs []string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail > 0 {
		p.fail--
		return errors.New("store unavailable")
	}
	if p.calls == nil {
		p.calls = map[string][]string{}
	}
	sorted := slices.Clone(peerIDs)
	slices.Sort(sorted)
	p.calls[accountID] = sorted
	return nil
}

func (p *recordedPushes) get() map[string][]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return maps.Clone(p.calls)
}

// newTestScheduler returns a scheduler whose timers never fire on their own, so a
// test drives it through fire.
func newTestScheduler(stopping bool, pushes *recordedPushes) *mapResyncScheduler {
	r := newMapResyncScheduler(time.Hour, func() bool { return stopping }, pushes.push)
	r.delay = func(time.Duration) time.Duration { return time.Hour }
	return r
}

func TestMapResyncScheduler(t *testing.T) {
	t.Run("peers of an account are pushed in one batch", func(t *testing.T) {
		pushes := &recordedPushes{}
		r := newTestScheduler(false, pushes)
		r.schedule("acc1", "p1")
		r.schedule("acc1", "p2")
		r.schedule("acc2", "p3")
		r.fire("acc1")
		r.fire("acc2")
		assert.Equal(t, map[string][]string{"acc1": {"p1", "p2"}, "acc2": {"p3"}}, pushes.get(), "one push per account")
	})

	t.Run("a failed push is retried a bounded number of times", func(t *testing.T) {
		pushes := &recordedPushes{fail: 1}
		r := newTestScheduler(false, pushes)
		r.schedule("acc", "p")
		r.fire("acc")
		assert.Empty(t, pushes.get(), "the first push failed")
		r.fire("acc")
		assert.Equal(t, map[string][]string{"acc": {"p"}}, pushes.get(), "the retry must push the same peers")

		pushes = &recordedPushes{fail: maxResyncAttempts}
		r = newTestScheduler(false, pushes)
		r.schedule("acc", "p")
		for range maxResyncAttempts {
			r.fire("acc")
		}
		r.mu.Lock()
		pending := len(r.pending)
		r.mu.Unlock()
		assert.Zero(t, pending, "the push must give up after its attempts")
	})

	t.Run("nothing is pushed while stopping", func(t *testing.T) {
		pushes := &recordedPushes{}
		r := newTestScheduler(true, pushes)
		r.schedule("acc", "p")
		r.fire("acc")
		assert.Empty(t, pushes.get(), "a stopping server must not push")
	})
}

// fakeSecrets serves a management key that a test can rotate.
type fakeSecrets struct {
	mu  sync.Mutex
	key wgtypes.Key
}

func (f *fakeSecrets) GenerateTurnToken() (*Token, error)           { return &Token{}, nil }
func (f *fakeSecrets) GenerateRelayToken() (*Token, error)          { return &Token{}, nil }
func (f *fakeSecrets) SetupRefresh(context.Context, string, string) {}
func (f *fakeSecrets) CancelRefresh(string)                         {}

func (f *fakeSecrets) GetWGKey() (wgtypes.Key, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.key, nil
}

func (f *fakeSecrets) rotate(t *testing.T) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.key = mustGenerateKey(t)
}

// fakeStream is the server side of a Sync stream.
type fakeStream struct {
	ctx context.Context
	mu  sync.Mutex
	err error
}

func (f *fakeStream) Send(*proto.EncryptedMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

func (f *fakeStream) Context() context.Context { return f.ctx }

func (f *fakeStream) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func newTrackerTestClient(t *testing.T) *redis.Client {
	t.Helper()
	ctx := context.Background()
	container, err := testcontainersredis.Run(ctx, "redis:7")
	require.NoError(t, err, "redis container must start")
	t.Cleanup(func() {
		if err := container.Terminate(ctx); err != nil {
			t.Logf("failed to terminate redis container: %v", err)
		}
	})
	url, err := container.ConnectionString(ctx)
	require.NoError(t, err)
	opts, err := redis.ParseURL(url)
	require.NoError(t, err)
	client := redis.NewClient(opts)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func newTrackerTestCache(client *redis.Client) *syncmapcache.Cache {
	return syncmapcache.New(client, syncmapcache.Config{Enabled: true, Generation: "test", MaxAge: time.Hour, ReleaseGrace: 50 * time.Millisecond})
}

// trackedStream is a running update handler whose stream owns a fresh cache entry.
type trackedStream struct {
	client  *redis.Client
	cache   *syncmapcache.Cache
	peerKey syncmapcache.PeerKey
	secrets *fakeSecrets
	srv     *fakeStream
	cancel  context.CancelFunc
	updates chan *network_map.UpdateMessage
	tracker *deliveryTracker
	done    chan struct{}
}

func startTrackedStream(t *testing.T, client *redis.Client, debounce time.Duration) *trackedStream {
	t.Helper()
	ctx := context.Background()
	cache := newTrackerTestCache(client)
	peerKey := mustGenerateKey(t)
	secrets := &fakeSecrets{key: mustGenerateKey(t)}
	serverKey, _ := secrets.GetWGKey()

	seen, err := cache.Lookup(ctx, cachePeerKey(peerKey), keyFingerprint(serverKey))
	require.NoError(t, err)
	require.NoError(t, cache.ClaimDelivered(ctx, cachePeerKey(peerKey), seen, 1, 5, keyFingerprint(serverKey)))

	srvCtx, cancel := context.WithCancel(ctx)
	ts := &trackedStream{
		client:  client,
		cache:   cache,
		peerKey: cachePeerKey(peerKey),
		secrets: secrets,
		srv:     &fakeStream{ctx: srvCtx},
		cancel:  cancel,
		updates: make(chan *network_map.UpdateMessage, 10),
		done:    make(chan struct{}),
		tracker: &deliveryTracker{
			cache:      cache,
			peerKey:    cachePeerKey(peerKey),
			session:    1,
			streamKey:  serverKey.PublicKey(),
			lastSerial: 5,
		},
	}
	cache.StreamStarted()
	pu := (&PeerUpdateHandler{
		peerKey:        peerKey,
		updates:        ts.updates,
		secretsManager: secrets,
		srv:            ts.srv,
		encrypter:      encryption.DefaultEncrypter{},
		debouncer:      NewUpdateDebouncer(debounce),
		cleanupFunc:    func() {},
	}).withDeliveryTracker(ts.tracker)
	go func() {
		defer close(ts.done)
		_ = pu.HandleUpdates(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-ts.done
	})
	return ts
}

// restart ends the stream the way a management shutdown does and reports whether
// the next instance may reuse the peer's map.
func (ts *trackedStream) restart(t *testing.T) (uint64, bool) {
	t.Helper()
	time.Sleep(100 * time.Millisecond)
	ts.cache.BeginShutdown()
	ts.cancel()
	<-ts.done
	return ts.reusableOnNextInstance(t)
}

func (ts *trackedStream) reusableOnNextInstance(t *testing.T) (uint64, bool) {
	t.Helper()
	key, _ := ts.secrets.GetWGKey()
	l, err := newTrackerTestCache(ts.client).Lookup(context.Background(), ts.peerKey, keyFingerprint(key))
	require.NoError(t, err)
	return l.Serial()
}

func mapUpdate(serial uint64) *network_map.UpdateMessage {
	return &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{NetworkMap: &proto.NetworkMap{Serial: serial}},
		MessageType: network_map.MessageTypeNetworkMap,
	}
}

// waitDrained waits until the handler took every queued update.
func (ts *trackedStream) waitDrained(t *testing.T) {
	t.Helper()
	require.Eventually(t, func() bool { return len(ts.updates) == 0 }, 5*time.Second, 10*time.Millisecond,
		"the handler must take the queued updates")
}

func TestPeerUpdateHandlerRecordsDeliveries(t *testing.T) {
	client := newTrackerTestClient(t)

	t.Run("a stream ended by the shutdown releases what it sent", func(t *testing.T) {
		ts := startTrackedStream(t, client, time.Millisecond)
		ts.updates <- mapUpdate(6)
		ts.waitDrained(t)
		serial, ok := ts.restart(t)
		require.True(t, ok, "the next instance must reuse the map of a stream the shutdown ended")
		assert.Equal(t, uint64(6), serial, "the released serial must be the last one sent")
		waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		ts.cache.WaitStreams(waitCtx)
		assert.NoError(t, waitCtx.Err(), "the ended stream must be uncounted")
	})

	t.Run("a stream that ends while the server runs releases nothing", func(t *testing.T) {
		ts := startTrackedStream(t, client, time.Millisecond)
		ts.cancel()
		<-ts.done
		_, ok := ts.reusableOnNextInstance(t)
		assert.False(t, ok, "a stream the client ended may have missed changes while it reconnects")
	})

	t.Run("a rotated management key keeps the stream from vouching", func(t *testing.T) {
		ts := startTrackedStream(t, client, time.Millisecond)
		ts.secrets.rotate(t)
		ts.updates <- &network_map.UpdateMessage{Update: &proto.SyncResponse{NetbirdConfig: &proto.NetbirdConfig{}}, MessageType: network_map.MessageTypeControlConfig}
		ts.waitDrained(t)
		_, ok := ts.restart(t)
		assert.False(t, ok, "a message the client cannot decrypt must keep the entry from being released")
	})

	t.Run("a dropped update keeps the stream from vouching", func(t *testing.T) {
		ts := startTrackedStream(t, client, time.Millisecond)
		ts.tracker.dropped.Store(true)
		_, ok := ts.restart(t)
		assert.False(t, ok, "a stream that lost an update must not release its entry")
	})

	t.Run("a failed send keeps the stream from vouching", func(t *testing.T) {
		ts := startTrackedStream(t, client, time.Millisecond)
		ts.srv.fail(errors.New("broken stream"))
		ts.updates <- mapUpdate(6)
		<-ts.done
		ts.cache.BeginShutdown()
		_, ok := ts.reusableOnNextInstance(t)
		assert.False(t, ok, "an update that never left must keep the entry from being released")
	})

	t.Run("a stream that ends with debounced updates keeps from vouching", func(t *testing.T) {
		ts := startTrackedStream(t, client, time.Hour)
		ts.updates <- mapUpdate(6)
		ts.waitDrained(t)
		// The second update waits out the debounce interval when the server stops.
		ts.updates <- mapUpdate(7)
		ts.waitDrained(t)
		_, ok := ts.restart(t)
		assert.False(t, ok, "an update the stream never sent must keep the entry from being released")
	})

	t.Run("a map sent right before the shutdown is not released", func(t *testing.T) {
		ts := startTrackedStream(t, client, time.Millisecond)
		ts.updates <- mapUpdate(6)
		ts.waitDrained(t)
		ts.cache.BeginShutdown()
		ts.cancel()
		<-ts.done
		_, ok := ts.reusableOnNextInstance(t)
		assert.False(t, ok, "frames still being flushed when the server stops may never reach the client")
	})
}

func TestOnUpdateDroppedMarksTheStream(t *testing.T) {
	s := &Server{}
	tracker := &deliveryTracker{session: 1}
	s.streamTrackers.Store("peer", tracker)

	s.OnUpdateDropped(context.Background(), "other")
	assert.False(t, tracker.dropped.Load(), "a drop for another peer must not mark the stream")

	s.OnUpdateDropped(context.Background(), "peer")
	assert.True(t, tracker.dropped.Load(), "a drop must keep the stream from vouching for the map")

	s.onSyncStreamEnded("peer", 2)
	_, ok := s.streamTrackers.Load("peer")
	assert.True(t, ok, "the end of another session must not unregister the stream")
	s.onSyncStreamEnded("peer", 1)
	_, ok = s.streamTrackers.Load("peer")
	assert.False(t, ok, "the end of the stream must unregister it")
}

func TestTakeOverMapEntry(t *testing.T) {
	client := newTrackerTestClient(t)
	ctx := context.Background()
	serverKey := mustGenerateKey(t)

	// released prepares a peer whose previous stream released its entry at serial 7,
	// as a restarted instance finds it.
	released := func(t *testing.T) (wgtypes.Key, mapReuseLookup) {
		t.Helper()
		peerKey := mustGenerateKey(t)
		old := newTrackerTestCache(client)
		seen, err := old.Lookup(ctx, cachePeerKey(peerKey), keyFingerprint(serverKey))
		require.NoError(t, err)
		require.NoError(t, old.ClaimDelivered(ctx, cachePeerKey(peerKey), seen, 1, 7, keyFingerprint(serverKey)))
		old.BeginShutdown()
		require.NoError(t, old.Release(ctx, cachePeerKey(peerKey), 1, time.Time{}))

		seen, err = newTrackerTestCache(client).Lookup(ctx, cachePeerKey(peerKey), keyFingerprint(serverKey))
		require.NoError(t, err)
		_, ok := seen.Serial()
		require.True(t, ok, "the released entry must be reusable before the Sync")
		return peerKey, mapReuseLookup{seen: seen, read: true, reuse: &types.MapReuse{Serial: 7}}
	}

	newServer := func() (*Server, *syncmapcache.Cache) {
		s := &Server{}
		c := newTrackerTestCache(client)
		s.syncMap.Store(&syncMapState{cache: c})
		return s, c
	}

	reusable := func(t *testing.T, c *syncmapcache.Cache, peerKey wgtypes.Key) bool {
		t.Helper()
		l, err := c.Lookup(ctx, cachePeerKey(peerKey), keyFingerprint(serverKey))
		require.NoError(t, err)
		_, ok := l.Serial()
		return ok
	}

	alive := &fakeStream{ctx: ctx}
	deadCtx, cancel := context.WithCancel(ctx)
	cancel()
	dead := &fakeStream{ctx: deadCtx}
	fullMap := initialDelivery{serial: 7, hasMap: true, key: serverKey}

	cases := []struct {
		name string
		srv  syncSender
		res  *types.PeerSyncResult
		d    initialDelivery
	}{
		{name: "a peer failing validation", srv: alive, res: &types.PeerSyncResult{PeerNotValid: true}, d: fullMap},
		{name: "a stream that died before the claim", srv: dead, res: &types.PeerSyncResult{}, d: fullMap},
		{name: "a response under another management key", srv: alive, res: &types.PeerSyncResult{}, d: initialDelivery{serial: 7, hasMap: true, key: mustGenerateKey(t)}},
		{name: "a full Sync that sent no map", srv: alive, res: &types.PeerSyncResult{}, d: initialDelivery{key: serverKey}},
	}
	for _, tc := range cases {
		t.Run(tc.name+" drops the released entry", func(t *testing.T) {
			peerKey, l := released(t)
			s, c := newServer()
			st := syncStream{peerKey: peerKey, serverKey: serverKey, peerID: "peer", session: 2, srv: tc.srv}
			assert.Nil(t, s.takeOverMapEntry(ctx, st, l, tc.res, tc.d), "the stream must not take the entry over")
			assert.False(t, reusable(t, c, peerKey), "the entry must not outlive a Sync that did not take it over")
		})
	}

	t.Run("a claim that lost to a login drops the entry", func(t *testing.T) {
		peerKey, l := released(t)
		s, c := newServer()
		require.NoError(t, c.OnLogin(ctx, cachePeerKey(peerKey)))
		st := syncStream{peerKey: peerKey, serverKey: serverKey, peerID: "peer", session: 2, srv: alive}
		assert.Nil(t, s.takeOverMapEntry(ctx, st, l, &types.PeerSyncResult{MapReused: true}, initialDelivery{key: serverKey}),
			"a stream that read the entry before a login must not take it over")
		assert.False(t, reusable(t, c, peerKey), "the entry must stay invalid")
	})

	t.Run("a reuse takes the entry over", func(t *testing.T) {
		peerKey, l := released(t)
		s, c := newServer()
		st := syncStream{peerKey: peerKey, serverKey: serverKey, peerID: "peer", session: 2, srv: alive}
		tracker := s.takeOverMapEntry(ctx, st, l, &types.PeerSyncResult{MapReused: true}, initialDelivery{key: serverKey})
		require.NotNil(t, tracker, "the stream must take the entry over")
		assert.Equal(t, uint64(7), tracker.lastSerial, "the stream holds the reused serial")
		assert.False(t, reusable(t, c, peerKey), "a taken-over entry is not reusable while its stream is open")
		tracker.ended()
	})
}
