package grpc

import (
	"context"
	"errors"
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

	resp := ToConfigOnlySyncResponse(cfg, peer, nil, relayToken, settings, nil, nil)

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

func TestMapResyncScheduler(t *testing.T) {
	type pushed struct {
		account string
		peers   []string
	}

	newScheduler := func(window time.Duration, stopping bool) (*mapResyncScheduler, func() []pushed) {
		var mu sync.Mutex
		var calls []pushed
		r := newMapResyncScheduler(window, func() bool { return stopping }, func(_ context.Context, accountID string, peerIDs []string) {
			mu.Lock()
			defer mu.Unlock()
			slices.Sort(peerIDs)
			calls = append(calls, pushed{account: accountID, peers: peerIDs})
		})
		return r, func() []pushed {
			mu.Lock()
			defer mu.Unlock()
			return slices.Clone(calls)
		}
	}

	t.Run("peers of an account are pushed in one batch", func(t *testing.T) {
		r, calls := newScheduler(50*time.Millisecond, false)
		r.schedule("acc1", "p1")
		r.schedule("acc1", "p2")
		r.schedule("acc2", "p3")

		require.Eventually(t, func() bool { return len(calls()) == 2 }, 2*time.Second, 10*time.Millisecond, "one push per account")
		got := calls()
		slices.SortFunc(got, func(a, b pushed) int {
			if a.account < b.account {
				return -1
			}
			return 1
		})
		assert.Equal(t, []pushed{{account: "acc1", peers: []string{"p1", "p2"}}, {account: "acc2", peers: []string{"p3"}}}, got, "batched pushes")
	})

	t.Run("nothing is pushed while stopping", func(t *testing.T) {
		r, calls := newScheduler(10*time.Millisecond, true)
		r.schedule("acc", "p")
		time.Sleep(100 * time.Millisecond)
		assert.Empty(t, calls(), "a stopping server must not push")
	})

	t.Run("a zero window disables the push", func(t *testing.T) {
		r, calls := newScheduler(0, false)
		r.schedule("acc", "p")
		time.Sleep(50 * time.Millisecond)
		assert.Empty(t, calls(), "no push without a window")
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

func newTrackerTestCache(t *testing.T) *syncmapcache.Cache {
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
	return syncmapcache.New(client, syncmapcache.Config{Enabled: true, Generation: "test", MaxAge: time.Hour})
}

// trackedStream is a running update handler whose stream owns a fresh cache entry.
type trackedStream struct {
	cache   *syncmapcache.Cache
	peerKey string
	secrets *fakeSecrets
	srv     *fakeStream
	cancel  context.CancelFunc
	updates chan *network_map.UpdateMessage
	done    chan struct{}
}

func startTrackedStream(t *testing.T, cache *syncmapcache.Cache, debounce time.Duration) *trackedStream {
	t.Helper()
	ctx := context.Background()
	peerKey := mustGenerateKey(t)
	secrets := &fakeSecrets{key: mustGenerateKey(t)}
	serverKey, _ := secrets.GetWGKey()

	seen, err := cache.Lookup(ctx, peerKey.PublicKey().String(), keyFingerprint(serverKey))
	require.NoError(t, err)
	require.NoError(t, cache.ClaimDelivered(ctx, peerKey.PublicKey().String(), seen, 1, 5, keyFingerprint(serverKey)))

	srvCtx, cancel := context.WithCancel(ctx)
	ts := &trackedStream{
		cache:   cache,
		peerKey: peerKey.PublicKey().String(),
		secrets: secrets,
		srv:     &fakeStream{ctx: srvCtx},
		cancel:  cancel,
		updates: make(chan *network_map.UpdateMessage, 10),
		done:    make(chan struct{}),
	}
	pu := &PeerUpdateHandler{
		peerKey:        peerKey,
		updates:        ts.updates,
		secretsManager: secrets,
		srv:            ts.srv,
		encrypter:      encryption.DefaultEncrypter{},
		debouncer:      NewUpdateDebouncer(debounce),
		cleanupFunc:    func() {},
		tracker: &deliveryTracker{
			cache:      cache,
			peerKey:    ts.peerKey,
			session:    1,
			streamKey:  serverKey.PublicKey(),
			lastSerial: 5,
		},
	}
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

func (ts *trackedStream) entry(t *testing.T) (uint64, bool) {
	t.Helper()
	key, _ := ts.secrets.GetWGKey()
	l, err := ts.cache.Lookup(context.Background(), ts.peerKey, keyFingerprint(key))
	require.NoError(t, err)
	return l.Serial()
}

func mapUpdate(serial uint64) *network_map.UpdateMessage {
	return &network_map.UpdateMessage{
		Update:      &proto.SyncResponse{NetworkMap: &proto.NetworkMap{Serial: serial}},
		MessageType: network_map.MessageTypeNetworkMap,
	}
}

func TestPeerUpdateHandlerRecordsDeliveries(t *testing.T) {
	cache := newTrackerTestCache(t)

	t.Run("a delivered map advances the entry", func(t *testing.T) {
		ts := startTrackedStream(t, cache, time.Millisecond)
		ts.updates <- mapUpdate(6)
		assert.Eventually(t, func() bool {
			serial, ok := ts.entry(t)
			return ok && serial == 6
		}, 5*time.Second, 10*time.Millisecond, "the entry must record the delivered serial")
	})

	t.Run("a rotated management key invalidates the entry", func(t *testing.T) {
		ts := startTrackedStream(t, cache, time.Millisecond)
		original, _ := ts.secrets.GetWGKey()
		ts.secrets.rotate(t)
		ts.updates <- &network_map.UpdateMessage{Update: &proto.SyncResponse{NetbirdConfig: &proto.NetbirdConfig{}}, MessageType: network_map.MessageTypeControlConfig}
		assert.Eventually(t, func() bool {
			l, err := ts.cache.Lookup(context.Background(), ts.peerKey, keyFingerprint(original))
			require.NoError(t, err)
			_, ok := l.Serial()
			return !ok
		}, 5*time.Second, 10*time.Millisecond, "a message the client cannot decrypt must invalidate the entry")
	})

	t.Run("a failed send invalidates the entry", func(t *testing.T) {
		ts := startTrackedStream(t, cache, time.Millisecond)
		ts.srv.fail(errors.New("broken stream"))
		ts.updates <- mapUpdate(6)
		<-ts.done
		_, ok := ts.entry(t)
		assert.False(t, ok, "an update that never left must invalidate the entry")
	})

	t.Run("a stream that ends with debounced updates invalidates the entry", func(t *testing.T) {
		ts := startTrackedStream(t, cache, time.Hour)
		ts.updates <- mapUpdate(6)
		require.Eventually(t, func() bool {
			serial, ok := ts.entry(t)
			return ok && serial == 6
		}, 5*time.Second, 10*time.Millisecond, "the first update is sent at once")

		// The second update waits out the debounce interval, then the stream ends.
		ts.updates <- mapUpdate(7)
		require.Eventually(t, func() bool { return len(ts.updates) == 0 }, 5*time.Second, 10*time.Millisecond)
		ts.cancel()
		<-ts.done
		_, ok := ts.entry(t)
		assert.False(t, ok, "an update the stream never sent must invalidate the entry")
	})
}
