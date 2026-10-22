package grpc

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/encryption"
	nbconfig "github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/account"
	"github.com/netbirdio/netbird/management/server/activity"
	nbcache "github.com/netbirdio/netbird/management/server/cache"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	nmdata "github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func newTestSyncMapCache(t *testing.T, enabled string) (*SyncMapCache, nbcache.Store) {
	t.Helper()
	t.Setenv(nbcache.RedisStoreEnvVar, "")
	t.Setenv(EnvSyncMapCacheEnabled, enabled)
	cacheStore, err := nbcache.NewStore(context.Background(), time.Hour, time.Minute, 10)
	require.NoError(t, err)
	return NewSyncMapCache(cacheStore), cacheStore
}

func TestSyncMapCacheRecordsSentMaps(t *testing.T) {
	ctx := context.Background()
	cache, cacheStore := newTestSyncMapCache(t, "true")

	assert.False(t, cache.canSkipMap(ctx, "peer", "0.80.0"), "a peer never sent a map must get one")

	cache.mapSent(ctx, "peer", 42)
	assert.True(t, cache.canSkipMap(ctx, "peer", "0.80.0"), "a peer sent a map since its last Login keeps it")
	value, err := cacheStore.Get(ctx, syncMapCacheKey("peer"))
	require.NoError(t, err)
	assert.Equal(t, "42", value, "the entry must hold the serial sent")

	assert.False(t, cache.canSkipMap(ctx, "other-peer", "0.80.0"), "entries must be per peer")
	assert.False(t, cache.canSkipMap(ctx, "peer", "0.72.2"), "a client that clears its checks must get the map")

	require.NoError(t, cache.forget(ctx, "peer"))
	assert.False(t, cache.canSkipMap(ctx, "peer", "0.80.0"), "a peer that logged in must get its map")
	require.NoError(t, cache.forget(ctx, "peer"), "forgetting a missing entry must succeed")
}

func TestSyncMapCacheDisabledOnlyForgets(t *testing.T) {
	ctx := context.Background()
	cache, cacheStore := newTestSyncMapCache(t, "false")

	cache.mapSent(ctx, "peer", 42)
	_, err := cacheStore.Get(ctx, syncMapCacheKey("peer"))
	assert.Error(t, err, "nothing must be recorded while the cache is off")

	enabled, _ := newTestSyncMapCache(t, "true")
	enabled.store = cacheStore
	enabled.mapSent(ctx, "peer", 42)
	assert.False(t, cache.canSkipMap(ctx, "peer", "0.80.0"), "the map must never be skipped while the cache is off")

	require.NoError(t, cache.forget(ctx, "peer"))
	assert.False(t, enabled.canSkipMap(ctx, "peer", "0.80.0"), "login must clear entries even while the cache is off")
}

func TestNilSyncMapCache(t *testing.T) {
	var cache *SyncMapCache
	ctx := context.Background()
	assert.False(t, cache.canSkipMap(ctx, "peer", "0.80.0"), "a server without a cache must always compute the map")
	cache.mapSent(ctx, "peer", 1)
	assert.NoError(t, cache.forget(ctx, "peer"), "a server without a cache must not fail logins")
}

func TestSyncMapCacheEnabledByEnv(t *testing.T) {
	for value, want := range map[string]bool{"": false, "true": true, "1": true, "false": false, "yes": false} {
		t.Setenv(EnvSyncMapCacheEnabled, value)
		assert.Equal(t, want, syncMapCacheEnabledByEnv(), "value %q", value)
	}
}

func TestClientKeepsStateOnConfigOnlySync(t *testing.T) {
	for version, want := range map[string]bool{
		"0.72.2":      false,
		"0.72.3":      true,
		"0.80.0":      true,
		"development": true,
		"":            false,
		"garbage":     false,
	} {
		assert.Equal(t, want, clientKeepsStateOnConfigOnlySync(version), "version %q", version)
	}
}

func TestSentMapSerial(t *testing.T) {
	assert.Zero(t, sentMapSerial(nil), "no map has no serial")
	assert.Zero(t, sentMapSerial(&types.NetworkMap{}), "a map without a network has no serial")
	assert.Equal(t, uint64(7), sentMapSerial(&types.NetworkMap{Network: &nmdata.Network{Serial: 7}}), "the network serial must be recorded")
}

func TestSyncMapResyncWindow(t *testing.T) {
	for value, want := range map[string]time.Duration{
		"":      defaultResyncWindow,
		"30s":   30 * time.Second,
		"2h":    maxResyncWindow,
		"0":     defaultResyncWindow,
		"-1m":   defaultResyncWindow,
		"bogus": defaultResyncWindow,
	} {
		t.Setenv(EnvSyncMapCacheResyncWindow, value)
		assert.Equal(t, want, syncMapResyncWindow(), "value %q", value)
	}
}

func TestUntilResyncTick(t *testing.T) {
	window := 10 * time.Minute
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

	for _, account := range []string{"a", "b", "account-with-a-long-id"} {
		d := untilResyncTick(account, window, now)
		assert.Greater(t, d, time.Duration(0), "the tick must be in the future")
		assert.LessOrEqual(t, d, window, "the tick must fall within one window")

		// Instances that compute the tick at different moments land on the same one.
		later := now.Add(3 * time.Minute)
		if d > 3*time.Minute {
			assert.Equal(t, now.Add(d), later.Add(untilResyncTick(account, window, later)), "instances must agree on the account's tick")
		}
		// The tick repeats every window.
		tick := now.Add(d)
		assert.Equal(t, window, untilResyncTick(account, window, tick), "at a tick the next one is a window away")
	}

	assert.NotEqual(t, untilResyncTick("a", window, now), untilResyncTick("b", window, now), "accounts must spread over the window")
}

// fakeResyncClock records the timers a scheduler arms so tests fire them directly.
type fakeResyncClock struct {
	now    time.Time
	timers []func()
	delays []time.Duration
}

func (c *fakeResyncClock) after(d time.Duration, f func()) {
	c.delays = append(c.delays, d)
	c.timers = append(c.timers, f)
}

func (c *fakeResyncClock) fireAll() {
	timers := c.timers
	c.timers = nil
	for _, f := range timers {
		f()
	}
}

type resyncPush struct {
	accountID string
	peerIDs   []string
}

func newTestResyncScheduler(fail *int) (*mapResyncScheduler, *fakeResyncClock, *[]resyncPush) {
	clock := &fakeResyncClock{now: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
	var pushes []resyncPush
	r := newMapResyncScheduler(10*time.Minute, func(_ context.Context, accountID string, peerIDs []string) error {
		pushes = append(pushes, resyncPush{accountID: accountID, peerIDs: slices.Sorted(slices.Values(peerIDs))})
		if *fail > 0 {
			*fail--
			return errors.New("push failed")
		}
		return nil
	})
	r.now = func() time.Time { return clock.now }
	r.after = clock.after
	return r, clock, &pushes
}

func TestMapResyncSchedulerBatchesByAccount(t *testing.T) {
	fail := 0
	r, clock, pushes := newTestResyncScheduler(&fail)

	r.schedule("acc-1", "p1")
	r.schedule("acc-1", "p2")
	r.schedule("acc-1", "p1")
	r.schedule("acc-2", "p3")
	require.Len(t, clock.timers, 2, "each account must arm one timer")
	assert.Equal(t, untilResyncTick("acc-1", 10*time.Minute, clock.now), clock.delays[0], "the push must wait for the account's tick")

	clock.fireAll()
	assert.ElementsMatch(t, []resyncPush{
		{accountID: "acc-1", peerIDs: []string{"p1", "p2"}},
		{accountID: "acc-2", peerIDs: []string{"p3"}},
	}, *pushes, "each account must get one push for all its peers")

	r.schedule("acc-1", "p4")
	require.Len(t, clock.timers, 1, "a resume after the push must wait for the next tick")
}

func TestMapResyncSchedulerRetries(t *testing.T) {
	fail := maxResyncAttempts
	r, clock, pushes := newTestResyncScheduler(&fail)

	r.schedule("acc-1", "p1")
	clock.fireAll()
	require.Len(t, clock.timers, 1, "a failed push must be retried at the next tick")

	// A peer that resumes before the retry joins it.
	r.schedule("acc-1", "p2")
	require.Len(t, clock.timers, 1, "the retry and the new resume must share the account's timer")
	clock.fireAll()
	assert.Equal(t, []string{"p1", "p2"}, (*pushes)[1].peerIDs, "the retry must carry the peer that joined")

	clock.fireAll()
	assert.Len(t, *pushes, maxResyncAttempts, "the push must be tried %d times", maxResyncAttempts)
	assert.Empty(t, clock.timers, "the scheduler must give up after the last attempt")
}

func TestNilMapResyncScheduler(t *testing.T) {
	var r *mapResyncScheduler
	assert.NotPanics(t, func() { r.schedule("acc", "peer") }, "a server without the cache must ignore resumes")
}

// capturingSyncServer records what a Sync handler sends.
type capturingSyncServer struct {
	grpc.ServerStream
	sent []*proto.EncryptedMessage
}

func (s *capturingSyncServer) Send(msg *proto.EncryptedMessage) error {
	s.sent = append(s.sent, msg)
	return nil
}

func TestSendConfigOnlySyncUsesMergedSettings(t *testing.T) {
	ctrl := gomock.NewController(t)
	accountManager := account.NewMockManager(ctrl)
	settingsManager := settings.NewMockManager(ctrl)
	secretsManager := NewMockSecretsManager(ctrl)
	storeMock := store.NewMockStore(ctrl)

	serverKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	peerKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	lastLogin := time.Now().UTC().Add(-time.Minute)
	peer := &nbpeer.Peer{ID: "peer-1", AccountID: "account-1", UserID: "user-1", LoginExpirationEnabled: true, LastLogin: &lastLogin}

	// Only the settings manager merges in the extra settings, such as traffic flow, that
	// the connection config is extended with; the strict store mock fails the test if the
	// response is built from the store's settings instead.
	merged := &types.Settings{PeerLoginExpirationEnabled: true, PeerLoginExpiration: time.Hour, Extra: &types.ExtraSettings{FlowEnabled: true}}
	settingsManager.EXPECT().GetSettings(gomock.Any(), "account-1", activity.SystemInitiator).Return(merged, nil)
	accountManager.EXPECT().GetStore().Return(storeMock)
	storeMock.EXPECT().GetPeerGroupIDs(gomock.Any(), store.LockingStrengthNone, "account-1", "peer-1").Return([]string{"group-1"}, nil)
	secretsManager.EXPECT().GetWGKey().Return(serverKey, nil)

	s := &Server{
		accountManager:  accountManager,
		settingsManager: settingsManager,
		secretsManager:  secretsManager,
		config:          &nbconfig.Config{Stuns: []*nbconfig.Host{{Proto: "udp", URI: "stun:stun.example.com:3478"}}},
	}
	srv := &capturingSyncServer{}
	require.NoError(t, s.sendConfigOnlySync(context.Background(), peerKey.PublicKey(), peer, srv))
	require.Len(t, srv.sent, 1, "one message must be sent")

	resp := &proto.SyncResponse{}
	require.NoError(t, encryption.DecryptMessage(serverKey.PublicKey(), peerKey, srv.sent[0].Body, resp))
	assert.Nil(t, resp.GetNetworkMap(), "a config-only response carries no map")
	assert.Nil(t, resp.GetPeerConfig(), "a config-only response carries no peer config")
	assert.Nil(t, resp.GetChecks(), "a config-only response carries no posture checks")
	require.NotNil(t, resp.GetNetbirdConfig(), "the connection config must be sent")
	assert.Len(t, resp.GetNetbirdConfig().GetStuns(), 1, "the connection config must come from the server config")
	assert.Equal(t, lastLogin.Add(time.Hour).Unix(), resp.GetSessionExpiresAt().GetSeconds(), "the session deadline must follow the merged settings")
}
