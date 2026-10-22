package server

import (
	"context"
	"errors"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/eko/gocache/lib/v4/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	testcontainersredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/management/internals/server/config"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	nbcache "github.com/netbirdio/netbird/management/server/cache"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	nbstore "github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	mgmtProto "github.com/netbirdio/netbird/shared/management/proto"
)

// newRedisCacheStore returns the shared cache store backed by a fresh Redis container.
func newRedisCacheStore(t *testing.T) nbcache.Store {
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
	t.Setenv(nbcache.RedisStoreEnvVar, url)

	cacheStore, err := nbcache.NewStore(ctx, time.Hour, time.Minute, 10)
	require.NoError(t, err, "redis cache store must connect")
	return cacheStore
}

func newMemoryCacheStore(t *testing.T) nbcache.Store {
	t.Helper()
	t.Setenv(nbcache.RedisStoreEnvVar, "")
	cacheStore, err := nbcache.NewStore(context.Background(), time.Hour, time.Minute, 10)
	require.NoError(t, err)
	return cacheStore
}

// failingDeleteStore fails every delete, as a cache store whose backend is down.
type failingDeleteStore struct {
	nbcache.Store
}

func (failingDeleteStore) Delete(context.Context, any) error {
	return errors.New("cache unavailable")
}

// syncMapTestPeer is a client of the management service that keeps the same system
// meta across Login and Sync, as a running engine does.
type syncMapTestPeer struct {
	t         *testing.T
	client    mgmtProto.ManagementServiceClient
	serverKey wgtypes.Key
	key       wgtypes.Key
	meta      *mgmtProto.PeerSystemMeta
}

func newSyncMapTestPeer(t *testing.T, addr string) *syncMapTestPeer {
	t.Helper()

	client, conn, err := createRawClient(addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	serverKey, err := getServerKey(client)
	require.NoError(t, err)
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	return &syncMapTestPeer{
		t:         t,
		client:    client,
		serverKey: *serverKey,
		key:       key,
		meta: &mgmtProto.PeerSystemMeta{
			Hostname:       "sync-map-cache",
			GoOS:           runtime.GOOS,
			OS:             runtime.GOOS,
			Core:           "core",
			Platform:       "platform",
			Kernel:         "kernel",
			NetbirdVersion: "0.80.0",
		},
	}
}

func (p *syncMapTestPeer) pubKey() string {
	return p.key.PublicKey().String()
}

func (p *syncMapTestPeer) login() error {
	p.t.Helper()
	msg, err := encryption.EncryptMessage(p.serverKey, p.key, &mgmtProto.LoginRequest{SetupKey: TestValidSetupKey, Meta: p.meta})
	require.NoError(p.t, err)
	_, err = p.client.Login(context.Background(), &mgmtProto.EncryptedMessage{WgPubKey: p.pubKey(), Body: msg})
	return err
}

// sync opens a Sync stream and returns its first message, or the error that ended it.
func (p *syncMapTestPeer) sync() (*mgmtProto.SyncResponse, mgmtProto.ManagementService_SyncClient, error) {
	p.t.Helper()
	msg, err := encryption.EncryptMessage(p.serverKey, p.key, &mgmtProto.SyncRequest{Meta: p.meta})
	require.NoError(p.t, err)

	ctx, cancel := context.WithCancel(context.Background())
	p.t.Cleanup(cancel)
	stream, err := p.client.Sync(ctx, &mgmtProto.EncryptedMessage{WgPubKey: p.pubKey(), Body: msg})
	require.NoError(p.t, err)

	resp, err := p.recv(stream)
	return resp, stream, err
}

// syncAndClose opens a Sync stream, returns its first message and closes the stream,
// as a client whose connection drops does.
func (p *syncMapTestPeer) syncAndClose() *mgmtProto.SyncResponse {
	p.t.Helper()
	resp, stream, err := p.sync()
	require.NoError(p.t, err, "sync must succeed")
	require.NoError(p.t, stream.CloseSend())
	return resp
}

func (p *syncMapTestPeer) recv(stream mgmtProto.ManagementService_SyncClient) (*mgmtProto.SyncResponse, error) {
	p.t.Helper()
	type received struct {
		msg *mgmtProto.EncryptedMessage
		err error
	}
	ch := make(chan received, 1)
	go func() {
		msg := &mgmtProto.EncryptedMessage{}
		err := stream.RecvMsg(msg)
		ch <- received{msg: msg, err: err}
	}()

	var r received
	select {
	case r = <-ch:
	case <-time.After(10 * time.Second):
		require.FailNow(p.t, "timed out waiting for a sync message")
	}
	if r.err != nil {
		return nil, r.err
	}
	resp := &mgmtProto.SyncResponse{}
	require.NoError(p.t, encryption.DecryptMessage(p.serverKey, p.key, r.msg.Body, resp))
	return resp, nil
}

func syncMapEntry(cacheStore nbcache.Store, peerKey string) (string, bool) {
	value, err := cacheStore.Get(context.Background(), "nb:syncmap:"+peerKey)
	if err != nil {
		return "", false
	}
	s, ok := value.(string)
	return s, ok
}

func waitForSyncMapEntry(t *testing.T, cacheStore nbcache.Store, peerKey, want string) {
	t.Helper()
	require.Eventually(t, func() bool {
		got, ok := syncMapEntry(cacheStore, peerKey)
		return ok && got == want
	}, 5*time.Second, 20*time.Millisecond, "the full map sent must be recorded with serial %s", want)
}

func startSyncMapCacheManagement(t *testing.T, cacheStore nbcache.Store) (*DefaultAccountManager, string) {
	t.Helper()
	syncMapCache := nbgrpc.NewSyncMapCache(cacheStore)
	mgmtServer, am, addr, cleanup, err := startManagementForTest(t, "testdata/store_with_expired_peers.sql", &config.Config{
		Stuns:   []*config.Host{{Proto: "udp", URI: "stun:stun.netbird.io:3468"}},
		Signal:  &config.Host{Proto: "http", URI: "signal.netbird.io:10000"},
		Datadir: t.TempDir(),
	}, func(s *nbgrpc.Server) { s.SetSyncMapCache(syncMapCache) })
	require.NoError(t, err)
	t.Cleanup(cleanup)
	t.Cleanup(mgmtServer.Stop)
	return am, addr
}

func TestSyncMapCache(t *testing.T) {
	t.Setenv(nbgrpc.EnvSyncMapCacheEnabled, "true")
	t.Setenv(nbgrpc.EnvSyncMapCacheResyncWindow, "300ms")
	cacheStore := newRedisCacheStore(t)
	am, addr := startSyncMapCacheManagement(t, cacheStore)
	ctx := context.Background()

	peer := newSyncMapTestPeer(t, addr)
	require.NoError(t, peer.login(), "login must succeed")
	accountID, err := am.GetAccountIDForPeerKey(ctx, peer.pubKey())
	require.NoError(t, err)

	// A fresh engine after Login gets its full map, and the server records it.
	resp := peer.syncAndClose()
	require.NotNil(t, resp.GetNetworkMap(), "the first Sync after Login must carry the full map")
	serial := resp.GetNetworkMap().GetSerial()
	waitForSyncMapEntry(t, cacheStore, peer.pubKey(), strconv.FormatUint(serial, 10))

	// The same engine reconnecting without Login keeps its map: it only gets the
	// connection config with fresh credentials.
	syncStart := time.Now().UTC()
	resp, stream, err := peer.sync()
	require.NoError(t, err, "a reconnect must succeed")
	assert.Nil(t, resp.GetNetworkMap(), "a reconnect must not carry a map")
	assert.Nil(t, resp.GetNetworkMapEnvelope(), "a reconnect must not carry a map envelope")
	assert.Nil(t, resp.GetPeerConfig(), "a reconnect must not carry a peer config")
	assert.Nil(t, resp.GetChecks(), "a reconnect must not carry posture checks")
	require.NotNil(t, resp.GetNetbirdConfig(), "a reconnect must carry the connection config")
	assert.NotEmpty(t, resp.GetNetbirdConfig().GetStuns(), "the connection config must be complete")
	assert.NotNil(t, resp.GetNetbirdConfig().GetSignal(), "the connection config must be complete")

	stored, err := am.Store.GetPeerByPeerPubKey(ctx, nbstore.LockingStrengthNone, peer.pubKey())
	require.NoError(t, err)
	assert.True(t, stored.Status.Connected, "a reconnect must mark the peer connected")
	assert.GreaterOrEqual(t, stored.Status.SessionStartedAt, syncStart.UnixNano(), "the reconnect must own the peer's session")

	// The peer gets a full map pushed by the end of the resync window, in case it missed
	// a change while disconnected.
	resynced, err := peer.recv(stream)
	require.NoError(t, err)
	require.NotNil(t, resynced.GetNetworkMap(), "a peer that resumed must get a full map within the resync window")
	assert.Equal(t, serial, resynced.GetNetworkMap().GetSerial(), "the resync must carry the current serial")

	// The resumed stream still receives the pushes that follow.
	require.NoError(t, am.Store.IncrementNetworkSerial(ctx, accountID))
	am.UpdateAccountPeers(ctx, accountID, types.UpdateReason{Resource: types.UpdateResourcePeer, Operation: types.UpdateOperationUpdate})
	pushed, err := peer.recv(stream)
	require.NoError(t, err)
	require.NotNil(t, pushed.GetNetworkMap(), "a push must carry the map")
	assert.Equal(t, serial+1, pushed.GetNetworkMap().GetSerial(), "the push must carry the new serial")
	require.NoError(t, stream.CloseSend())

	// Login clears the entry, so the new engine gets its full map.
	require.NoError(t, peer.login(), "login must succeed")
	_, found := syncMapEntry(cacheStore, peer.pubKey())
	assert.False(t, found, "login must clear the peer's entry before it returns")
	resp = peer.syncAndClose()
	require.NotNil(t, resp.GetNetworkMap(), "the first Sync after Login must carry the full map")
	waitForSyncMapEntry(t, cacheStore, peer.pubKey(), strconv.FormatUint(serial+1, 10))

	// A peer whose login expired is sent back to Login even when it holds a map.
	stored, err = am.Store.GetPeerByPeerPubKey(ctx, nbstore.LockingStrengthNone, peer.pubKey())
	require.NoError(t, err)
	require.NoError(t, am.Store.SavePeerStatus(ctx, accountID, stored.ID, nbpeer.PeerStatus{LoginExpired: true, LastSeen: time.Now().UTC()}))
	_, _, err = peer.sync()
	require.Error(t, err, "an expired peer must not resume")
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "the client must log in again")
	require.NoError(t, am.Store.SavePeerStatus(ctx, accountID, stored.ID, nbpeer.PeerStatus{LastSeen: time.Now().UTC()}))

	// Clients that clear their posture checks on a response without a map always get
	// the full map.
	peer.meta.NetbirdVersion = "0.72.2"
	for range 2 {
		resp = peer.syncAndClose()
		require.NotNil(t, resp.GetNetworkMap(), "an old client must never get a response without a map")
	}
}

func TestSyncMapCacheDisabled(t *testing.T) {
	cacheStore := newMemoryCacheStore(t)
	_, addr := startSyncMapCacheManagement(t, cacheStore)

	peer := newSyncMapTestPeer(t, addr)
	require.NoError(t, peer.login(), "login must succeed")
	for range 2 {
		resp := peer.syncAndClose()
		require.NotNil(t, resp.GetNetworkMap(), "every Sync must carry the full map while the cache is off")
	}
	_, found := syncMapEntry(cacheStore, peer.pubKey())
	assert.False(t, found, "nothing is recorded while the cache is off")

	// An instance with the cache off still clears the entry another instance wrote.
	require.NoError(t, cacheStore.Set(context.Background(), "nb:syncmap:"+peer.pubKey(), "1", store.WithExpiration(time.Hour)))
	require.NoError(t, peer.login(), "login must succeed")
	_, found = syncMapEntry(cacheStore, peer.pubKey())
	assert.False(t, found, "login must clear the entry even while the cache is off")
}

func TestSyncMapCacheLoginFailsClosed(t *testing.T) {
	t.Run("enabled", func(t *testing.T) {
		t.Setenv(nbgrpc.EnvSyncMapCacheEnabled, "true")
		_, addr := startSyncMapCacheManagement(t, failingDeleteStore{newMemoryCacheStore(t)})

		err := newSyncMapTestPeer(t, addr).login()
		require.Error(t, err, "a login whose entry cannot be cleared must fail")
		assert.Equal(t, codes.Unavailable, status.Code(err), "the client must retry the login")
	})

	t.Run("disabled", func(t *testing.T) {
		_, addr := startSyncMapCacheManagement(t, failingDeleteStore{newMemoryCacheStore(t)})
		assert.NoError(t, newSyncMapTestPeer(t, addr).login(), "the cache must not fail logins while it is off")
	})
}

func TestResumePeerSync(t *testing.T) {
	ctx := context.Background()
	manager, _, account, peer, _, _ := setupNetworkMapTest(t)

	t.Run("marks the peer connected without computing a map", func(t *testing.T) {
		syncTime := time.Now().UTC()
		resumed, ok, err := manager.ResumePeerSync(ctx, account.Id, peer.Key, syncTime)
		require.NoError(t, err)
		require.True(t, ok, "the peer must resume")
		assert.Equal(t, peer.ID, resumed.ID, "the resumed peer must be returned")

		stored, err := manager.Store.GetPeerByID(ctx, nbstore.LockingStrengthNone, account.Id, peer.ID)
		require.NoError(t, err)
		assert.True(t, stored.Status.Connected, "the peer must be marked connected")
		assert.Equal(t, syncTime.UnixNano(), stored.Status.SessionStartedAt, "the stream must own the peer's session")
	})

	t.Run("rejects an unknown peer", func(t *testing.T) {
		key, err := wgtypes.GeneratePrivateKey()
		require.NoError(t, err)
		_, ok, err := manager.ResumePeerSync(ctx, account.Id, key.PublicKey().String(), time.Now().UTC())
		assert.Error(t, err, "an unknown peer must be rejected")
		assert.False(t, ok, "an unknown peer must not resume")
	})

	t.Run("rejects a peer whose owner is blocked", func(t *testing.T) {
		blocked := &types.User{Id: "blocked-user", AccountID: account.Id, Role: types.UserRoleUser, Blocked: true}
		require.NoError(t, manager.Store.SaveUser(ctx, blocked))
		owned, err := manager.Store.GetPeerByID(ctx, nbstore.LockingStrengthNone, account.Id, peer.ID)
		require.NoError(t, err)
		owned.UserID = blocked.Id
		require.NoError(t, manager.Store.SavePeer(ctx, account.Id, owned))
		t.Cleanup(func() {
			owned.UserID = ""
			require.NoError(t, manager.Store.SavePeer(ctx, account.Id, owned))
		})

		_, ok, err := manager.ResumePeerSync(ctx, account.Id, peer.Key, time.Now().UTC())
		require.Error(t, err, "a peer of a blocked user must be rejected")
		assert.Contains(t, err.Error(), "blocked", "the rejection must name the blocked owner")
		assert.False(t, ok, "a peer of a blocked user must not resume")
	})

	t.Run("rejects a peer marked login expired", func(t *testing.T) {
		require.NoError(t, manager.Store.SavePeerStatus(ctx, account.Id, peer.ID, nbpeer.PeerStatus{LoginExpired: true, LastSeen: time.Now().UTC()}))
		t.Cleanup(func() {
			require.NoError(t, manager.Store.SavePeerStatus(ctx, account.Id, peer.ID, nbpeer.PeerStatus{LastSeen: time.Now().UTC()}))
		})

		_, ok, err := manager.ResumePeerSync(ctx, account.Id, peer.Key, time.Now().UTC())
		require.Error(t, err, "an expired peer must be rejected")
		assert.Contains(t, err.Error(), "expired", "the rejection must send the peer back to login")
		assert.False(t, ok, "an expired peer must not resume")
	})

	t.Run("leaves embedded proxy peers to the full sync", func(t *testing.T) {
		embedded, err := manager.Store.GetPeerByID(ctx, nbstore.LockingStrengthNone, account.Id, peer.ID)
		require.NoError(t, err)
		embedded.ProxyMeta.Embedded = true
		require.NoError(t, manager.Store.SavePeer(ctx, account.Id, embedded))
		before := embedded.Status.SessionStartedAt

		_, ok, err := manager.ResumePeerSync(ctx, account.Id, peer.Key, time.Now().UTC())
		require.NoError(t, err)
		assert.False(t, ok, "an embedded proxy peer must take the full sync")

		stored, err := manager.Store.GetPeerByID(ctx, nbstore.LockingStrengthNone, account.Id, peer.ID)
		require.NoError(t, err)
		assert.Equal(t, before, stored.Status.SessionStartedAt, "a peer left to the full sync must not be marked connected yet")
	})
}
