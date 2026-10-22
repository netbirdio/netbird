package server

import (
	"context"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	testcontainersredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/management/internals/server/config"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	"github.com/netbirdio/netbird/management/internals/shared/syncmapcache"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	mgmtProto "github.com/netbirdio/netbird/shared/management/proto"
)

func startSyncMapCacheRedis(t *testing.T) *redis.Client {
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

// syncMapTestPeer is a client of the management service that keeps the same system
// meta across Login and Sync, as a running engine does.
type syncMapTestPeer struct {
	t         *testing.T
	client    mgmtProto.ManagementServiceClient
	serverKey wgtypes.Key
	key       wgtypes.Key
	meta      *mgmtProto.PeerSystemMeta
}

func (p *syncMapTestPeer) login() {
	p.t.Helper()
	msg, err := encryption.EncryptMessage(p.serverKey, p.key, &mgmtProto.LoginRequest{SetupKey: TestValidSetupKey, Meta: p.meta})
	require.NoError(p.t, err)
	_, err = p.client.Login(context.Background(), &mgmtProto.EncryptedMessage{WgPubKey: p.key.PublicKey().String(), Body: msg})
	require.NoError(p.t, err, "login must succeed")
}

// sync opens a Sync stream and returns the initial response and the stream.
func (p *syncMapTestPeer) sync() (*mgmtProto.SyncResponse, mgmtProto.ManagementService_SyncClient, context.CancelFunc) {
	p.t.Helper()
	msg, err := encryption.EncryptMessage(p.serverKey, p.key, &mgmtProto.SyncRequest{Meta: p.meta})
	require.NoError(p.t, err)

	ctx, cancel := context.WithCancel(context.Background())
	stream, err := p.client.Sync(ctx, &mgmtProto.EncryptedMessage{WgPubKey: p.key.PublicKey().String(), Body: msg})
	require.NoError(p.t, err)
	return p.recv(stream), stream, cancel
}

func (p *syncMapTestPeer) recv(stream mgmtProto.ManagementService_SyncClient) *mgmtProto.SyncResponse {
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
	require.NoError(p.t, r.err)
	resp := &mgmtProto.SyncResponse{}
	require.NoError(p.t, encryption.DecryptMessage(p.serverKey, p.key, r.msg.Body, resp))
	return resp
}

// recordedEntry reads the stream that owns the peer's entry and the serial it
// recorded, whether or not the entry is reusable yet. A failed read reads as empty,
// so the callers' polling retries it.
func recordedEntry(client *redis.Client, p *syncMapTestPeer) (session string, serial string) {
	vals, err := client.HMGet(context.Background(), "nb:syncmap:"+p.key.PublicKey().String(), "sess", "serial").Result()
	if err != nil {
		return "", ""
	}
	session, _ = vals[0].(string)
	serial, _ = vals[1].(string)
	return session, serial
}

// syncAndClaim opens a Sync stream and waits until the stream took the peer's entry
// over, so a following restart can release it.
func (p *syncMapTestPeer) syncAndClaim(client *redis.Client) (*mgmtProto.SyncResponse, mgmtProto.ManagementService_SyncClient, context.CancelFunc) {
	p.t.Helper()
	before, _ := recordedEntry(client, p)
	resp, stream, cancel := p.sync()
	require.Eventually(p.t, func() bool {
		session, _ := recordedEntry(client, p)
		return session != "" && session != before
	}, 5*time.Second, 20*time.Millisecond, "the stream must take the entry over")
	return resp, stream, cancel
}

func waitForRecordedSerial(t *testing.T, client *redis.Client, p *syncMapTestPeer, serial uint64) {
	t.Helper()
	want := strconv.FormatUint(serial, 10)
	require.Eventually(t, func() bool {
		_, recorded := recordedEntry(client, p)
		return recorded == want
	}, 5*time.Second, 20*time.Millisecond, "the stream must record serial %d", serial)
}

func newTestSyncMapCache(client *redis.Client) *syncmapcache.Cache {
	return syncmapcache.New(client, syncmapcache.Config{
		Enabled:      true,
		Generation:   "test",
		MaxAge:       time.Hour,
		ResyncWindow: 200 * time.Millisecond,
		ReleaseGrace: 10 * time.Millisecond,
	})
}

// syncMapRestarter simulates management restarts: it shuts the server's cache down,
// lets the open stream end and release its entry, then hands the server a fresh
// cache as the next instance would have.
type syncMapRestarter struct {
	t      *testing.T
	client *redis.Client
	server *nbgrpc.Server
	cache  *syncmapcache.Cache
	peer   *syncMapTestPeer
}

func (r *syncMapRestarter) restart(cancelStream context.CancelFunc) {
	r.t.Helper()
	time.Sleep(50 * time.Millisecond)
	r.cache.BeginShutdown()
	cancelStream()

	next := newTestSyncMapCache(r.client)
	require.Eventually(r.t, func() bool {
		l, err := next.Lookup(context.Background(), syncmapcache.PeerKey(r.peer.key.PublicKey().String()), syncmapcache.KeyFingerprint(r.peer.serverKey.String()))
		if err != nil {
			return false
		}
		_, ok := l.Serial()
		return ok
	}, 5*time.Second, 20*time.Millisecond, "a stream ended by the shutdown must release its entry")

	r.cache = next
	r.server.SetSyncMapCache(next)
}

func TestSyncMapCache(t *testing.T) {
	redisClient := startSyncMapCacheRedis(t)
	cache := newTestSyncMapCache(redisClient)

	var grpcServer *nbgrpc.Server
	mgmtServer, am, addr, cleanup, err := startManagementForTest(t, "testdata/store_with_expired_peers.sql", &config.Config{
		Stuns:   []*config.Host{{Proto: "udp", URI: "stun:stun.netbird.io:3468"}},
		Signal:  &config.Host{Proto: "http", URI: "signal.netbird.io:10000"},
		Datadir: t.TempDir(),
	}, func(s *nbgrpc.Server) {
		grpcServer = s
		s.SetSyncMapCache(cache)
	})
	require.NoError(t, err)
	t.Cleanup(cleanup)
	t.Cleanup(mgmtServer.Stop)

	client, conn, err := createRawClient(addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	serverKey, err := getServerKey(client)
	require.NoError(t, err)
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	peer := &syncMapTestPeer{
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
	restarter := &syncMapRestarter{t: t, client: redisClient, server: grpcServer, cache: cache, peer: peer}
	peer.login()

	ctx := context.Background()
	accountID, err := am.GetAccountIDForPeerKey(ctx, key.PublicKey().String())
	require.NoError(t, err)

	// A fresh engine after Login gets its full map.
	resp, stream, cancel := peer.syncAndClaim(redisClient)
	require.NotNil(t, resp.GetNetworkMap(), "the first Sync after Login must carry the full map")
	serial := resp.GetNetworkMap().GetSerial()
	waitForRecordedSerial(t, redisClient, peer, serial)

	// A change pushed while the stream is up advances the recorded serial.
	require.NoError(t, am.Store.IncrementNetworkSerial(ctx, accountID))
	am.UpdateAccountPeers(ctx, accountID, types.UpdateReason{Resource: types.UpdateResourcePeer, Operation: types.UpdateOperationUpdate})
	pushed := peer.recv(stream)
	require.NotNil(t, pushed.GetNetworkMap(), "the push must carry a map")
	require.Equal(t, serial+1, pushed.GetNetworkMap().GetSerial(), "the push must carry the new serial")
	serial++
	waitForRecordedSerial(t, redisClient, peer, serial)

	// A client that reconnects while its old stream still looks open gets its full
	// map: the old stream may be dead behind a proxy with pushes that never arrived.
	resp, _, cancelReconnected := peer.sync()
	require.NotNil(t, resp.GetNetworkMap(), "a reconnect while the old stream looks open must carry the full map")
	cancel()
	cancelReconnected()

	// A stream that ends while the server keeps running (a client blip) releases
	// nothing, so the reconnect computes the map again.
	resp, _, cancel = peer.syncAndClaim(redisClient)
	require.NotNil(t, resp.GetNetworkMap(), "a reconnect after a client blip must carry the full map")

	// After a restart the peer reuses its map, and gets a full one pushed within the
	// resync window.
	restarter.restart(cancel)
	resp, stream, cancel = peer.syncAndClaim(redisClient)
	assert.Nil(t, resp.GetNetworkMap(), "a reconnect after a restart must not carry a map")
	assert.Nil(t, resp.GetNetworkMapEnvelope(), "a reconnect after a restart must not carry a map envelope")
	assert.Zero(t, resp.GetVersion(), "the response must be readable by every client as config-only")
	assert.Nil(t, resp.GetPeerConfig(), "a peer config without auto-update settings would change the client's updater mode")
	require.NotNil(t, resp.GetNetbirdConfig(), "the reconnect must still carry the connection config")
	assert.NotEmpty(t, resp.GetNetbirdConfig().GetStuns(), "the connection config must be complete")

	resynced := peer.recv(stream)
	require.NotNil(t, resynced.GetNetworkMap(), "a peer that reused its map must get a full map pushed later")
	assert.Equal(t, serial, resynced.GetNetworkMap().GetSerial(), "the resync must carry the current serial")

	// A change made while the peer was away is never skipped.
	restarter.restart(cancel)
	require.NoError(t, am.Store.IncrementNetworkSerial(ctx, accountID))
	serial++
	resp, _, cancel = peer.syncAndClaim(redisClient)
	require.NotNil(t, resp.GetNetworkMap(), "a serial change while away must force the full map")
	assert.Equal(t, serial, resp.GetNetworkMap().GetSerial(), "the full map must carry the current serial")

	// A peer whose own meta changed gets its map computed again.
	restarter.restart(cancel)
	peer.meta.Hostname = "renamed"
	resp, _, cancel = peer.syncAndClaim(redisClient)
	require.NotNil(t, resp.GetNetworkMap(), "a meta change must force the full map")

	// A new engine after Login always gets its full map.
	restarter.restart(cancel)
	peer.login()
	resp, _, cancel = peer.syncAndClaim(redisClient)
	require.NotNil(t, resp.GetNetworkMap(), "a Sync after Login must carry the full map")

	// Clients that clear their posture checks on a response without a map always
	// get the full map.
	peer.meta.NetbirdVersion = "0.72.2"
	restarter.restart(cancel)
	resp, _, cancel = peer.syncAndClaim(redisClient)
	require.NotNil(t, resp.GetNetworkMap(), "the version change itself is a meta change")
	restarter.restart(cancel)
	resp, _, cancel = peer.sync()
	require.NotNil(t, resp.GetNetworkMap(), "an old client must never get a response without a map")
	cancel()
}

func TestSyncMapCacheLoginFailsClosed(t *testing.T) {
	deadRedis := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 100 * time.Millisecond, MaxRetries: -1})
	t.Cleanup(func() { _ = deadRedis.Close() })
	cache := syncmapcache.New(deadRedis, syncmapcache.Config{Enabled: true, Generation: "test"})

	mgmtServer, _, addr, cleanup, err := startManagementForTest(t, "testdata/store_with_expired_peers.sql", &config.Config{
		Datadir: t.TempDir(),
	}, func(s *nbgrpc.Server) { s.SetSyncMapCache(cache) })
	require.NoError(t, err)
	t.Cleanup(cleanup)
	t.Cleanup(mgmtServer.Stop)

	client, conn, err := createRawClient(addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	_, err = loginPeerWithValidSetupKey(key, client)
	require.Error(t, err, "a login whose invalidation cannot be recorded must fail")
	assert.Equal(t, codes.Unavailable, status.Code(err), "the client must retry the login")
}

// invalidPeerValidator fails integrated validation for every peer.
type invalidPeerValidator struct {
	MockIntegratedValidator
}

func (invalidPeerValidator) IsNotValidPeer(context.Context, string, *nbpeer.Peer, []string, *types.ExtraSettings) (bool, bool, error) {
	return true, false, nil
}

// revalidatedPeerValidator reports every peer as valid after a fresh validation, as
// when a peer just became compliant.
type revalidatedPeerValidator struct {
	MockIntegratedValidator
}

func (revalidatedPeerValidator) IsNotValidPeer(context.Context, string, *nbpeer.Peer, []string, *types.ExtraSettings) (bool, bool, error) {
	return false, true, nil
}

func TestSyncAndMarkPeerMapReuse(t *testing.T) {
	ctx := context.Background()
	manager, _, account, _, peer, _ := setupNetworkMapTest(t)

	network, err := manager.Store.GetAccountNetwork(ctx, store.LockingStrengthNone, account.Id)
	require.NoError(t, err)
	current := &types.MapReuse{Serial: network.CurrentSerial()}

	t.Run("an unchanged peer holding the current serial skips the computation", func(t *testing.T) {
		res, err := manager.SyncAndMarkPeer(ctx, account.Id, peer.Key, peer.Meta, nil, time.Now().UTC(), current)
		require.NoError(t, err)
		assert.True(t, res.MapReused, "the map must be reused")
		assert.Nil(t, res.NetworkMap, "a reused map is not computed")
		assert.Equal(t, peer.ID, res.Peer.ID, "the synced peer must be returned")
	})

	t.Run("a reused map still marks the peer connected", func(t *testing.T) {
		syncTime := time.Now().UTC()
		res, err := manager.SyncAndMarkPeer(ctx, account.Id, peer.Key, peer.Meta, nil, syncTime, current)
		require.NoError(t, err)
		require.True(t, res.MapReused, "the map must be reused")

		stored, err := manager.Store.GetPeerByID(ctx, store.LockingStrengthNone, account.Id, peer.ID)
		require.NoError(t, err)
		assert.True(t, stored.Status.Connected, "the peer must be marked connected")
		assert.Equal(t, syncTime.UnixNano(), stored.Status.SessionStartedAt, "the stream must own the peer's session")
	})

	t.Run("a validation status change computes the map", func(t *testing.T) {
		original := manager.integratedPeerValidator
		manager.integratedPeerValidator = revalidatedPeerValidator{}
		t.Cleanup(func() { manager.integratedPeerValidator = original })

		res, err := manager.SyncAndMarkPeer(ctx, account.Id, peer.Key, peer.Meta, nil, time.Now().UTC(), current)
		require.NoError(t, err)
		assert.False(t, res.MapReused, "a peer whose validation just changed must get its map")
		assert.NotNil(t, res.NetworkMap, "the map must be computed")
	})

	t.Run("an older serial computes the map", func(t *testing.T) {
		res, err := manager.SyncAndMarkPeer(ctx, account.Id, peer.Key, peer.Meta, nil, time.Now().UTC(), &types.MapReuse{Serial: current.Serial - 1})
		require.NoError(t, err)
		assert.False(t, res.MapReused, "a peer behind the account serial must get its map")
		assert.NotNil(t, res.NetworkMap, "the map must be computed")
	})

	t.Run("no reuse candidate computes the map", func(t *testing.T) {
		res, err := manager.SyncAndMarkPeer(ctx, account.Id, peer.Key, peer.Meta, nil, time.Now().UTC(), nil)
		require.NoError(t, err)
		assert.False(t, res.MapReused, "a peer without a delivered map must get its map")
		assert.NotNil(t, res.NetworkMap, "the map must be computed")
	})

	t.Run("a meta change computes the map", func(t *testing.T) {
		meta := peer.Meta
		meta.Hostname = "changed-" + meta.Hostname
		res, err := manager.SyncAndMarkPeer(ctx, account.Id, peer.Key, meta, nil, time.Now().UTC(), current)
		require.NoError(t, err)
		assert.False(t, res.MapReused, "a peer whose meta changed must get its map")
		assert.NotNil(t, res.NetworkMap, "the map must be computed")
		peer.Meta = meta
	})

	t.Run("a peer failing validation computes its empty map", func(t *testing.T) {
		original := manager.integratedPeerValidator
		manager.integratedPeerValidator = invalidPeerValidator{}
		t.Cleanup(func() { manager.integratedPeerValidator = original })

		res, err := manager.SyncAndMarkPeer(ctx, account.Id, peer.Key, peer.Meta, nil, time.Now().UTC(), current)
		require.NoError(t, err)
		assert.False(t, res.MapReused, "an invalid peer must not keep its previous map")
		assert.True(t, res.PeerNotValid, "the result must report the invalid peer so its entry is dropped")
	})

	t.Run("an expired peer is rejected before any reuse", func(t *testing.T) {
		require.NoError(t, manager.Store.SavePeerStatus(ctx, account.Id, peer.ID, nbpeer.PeerStatus{LoginExpired: true, LastSeen: time.Now().UTC()}))
		_, err := manager.SyncAndMarkPeer(ctx, account.Id, peer.Key, peer.Meta, nil, time.Now().UTC(), current)
		assert.Error(t, err, "an expired peer must be sent back to login even when its map could be reused")
	})
}
