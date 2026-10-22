package server

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	testcontainersredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

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

// waitForEntry polls the peer's cache entry until check accepts it.
func waitForEntry(t *testing.T, c *syncmapcache.Cache, p *syncMapTestPeer, msg string, check func(serial uint64, reusable bool) bool) {
	t.Helper()
	assert.Eventually(t, func() bool {
		l, err := c.Lookup(context.Background(), p.key.PublicKey().String(), syncmapcache.KeyFingerprint(p.serverKey.String()))
		if err != nil {
			return false
		}
		serial, ok := l.Serial()
		return check(serial, ok)
	}, 5*time.Second, 50*time.Millisecond, msg)
}

func TestSyncMapCache(t *testing.T) {
	redisClient := startSyncMapCacheRedis(t)
	cache := syncmapcache.New(redisClient, syncmapcache.Config{
		Enabled:      true,
		Generation:   "test",
		MaxAge:       time.Hour,
		ResyncWindow: 200 * time.Millisecond,
	})

	mgmtServer, am, addr, cleanup, err := startManagementForTest(t, "testdata/store_with_expired_peers.sql", &config.Config{
		Stuns:   []*config.Host{{Proto: "udp", URI: "stun:stun.netbird.io:3468"}},
		Signal:  &config.Host{Proto: "http", URI: "signal.netbird.io:10000"},
		Datadir: t.TempDir(),
	}, func(s *nbgrpc.Server) { s.SetSyncMapCache(cache) })
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
	peer.login()

	ctx := context.Background()
	accountID, err := am.GetAccountIDForPeerKey(ctx, key.PublicKey().String())
	require.NoError(t, err)

	// A fresh engine after Login gets its full map.
	resp, stream, cancel := peer.sync()
	require.NotNil(t, resp.GetNetworkMap(), "the first Sync after Login must carry the full map")
	serial := resp.GetNetworkMap().GetSerial()
	waitForEntry(t, cache, peer, "the delivered map must be recorded", func(s uint64, ok bool) bool { return ok && s == serial })

	// A change pushed while the stream is up advances the recorded serial.
	require.NoError(t, am.Store.IncrementNetworkSerial(ctx, accountID))
	am.UpdateAccountPeers(ctx, accountID, types.UpdateReason{Resource: types.UpdateResourcePeer, Operation: types.UpdateOperationUpdate})
	pushed := peer.recv(stream)
	require.NotNil(t, pushed.GetNetworkMap(), "the push must carry a map")
	require.Equal(t, serial+1, pushed.GetNetworkMap().GetSerial(), "the push must carry the new serial")
	serial++
	waitForEntry(t, cache, peer, "the pushed map must advance the entry", func(s uint64, ok bool) bool { return ok && s == serial })

	// A client that reconnects before the server noticed its old stream died reuses
	// its map, and gets a full one pushed within the resync window.
	resp, reconnected, cancelReconnected := peer.sync()
	assert.Nil(t, resp.GetNetworkMap(), "a reconnect holding the current map must not carry a map")
	assert.Nil(t, resp.GetNetworkMapEnvelope(), "a reconnect holding the current map must not carry a map envelope")
	assert.Zero(t, resp.GetVersion(), "the response must be readable by every client as config-only")
	assert.Nil(t, resp.GetPeerConfig(), "a peer config without auto-update settings would change the client's updater mode")
	require.NotNil(t, resp.GetNetbirdConfig(), "the reconnect must still carry the connection config")
	assert.NotEmpty(t, resp.GetNetbirdConfig().GetStuns(), "the connection config must be complete")

	resynced := peer.recv(reconnected)
	require.NotNil(t, resynced.GetNetworkMap(), "a peer that reused its map must get a full map pushed later")
	assert.Equal(t, serial, resynced.GetNetworkMap().GetSerial(), "the resync must carry the current serial")
	cancel()

	// A stream that ends while the server keeps running (a client blip) leaves no
	// reusable entry: the peer may miss changes while it reconnects.
	cancelReconnected()
	waitForEntry(t, cache, peer, "a stream ended by the client must invalidate the entry", func(_ uint64, ok bool) bool { return !ok })

	resp, _, cancel = peer.sync()
	require.NotNil(t, resp.GetNetworkMap(), "a reconnect after a client blip must carry the full map")
	waitForEntry(t, cache, peer, "the delivered map must be recorded", func(s uint64, ok bool) bool { return ok && s == serial })

	// From here the server is stopping: streams that end keep their entries, as on a
	// management restart.
	cache.BeginShutdown()
	cancel()

	resp, _, cancel = peer.sync()
	assert.Nil(t, resp.GetNetworkMap(), "a reconnect after a restart must not carry a map")
	require.NotNil(t, resp.GetNetbirdConfig(), "a reconnect after a restart must carry the connection config")
	cancel()

	// A change made while the peer was away is never skipped.
	require.NoError(t, am.Store.IncrementNetworkSerial(ctx, accountID))
	serial++
	resp, _, cancel = peer.sync()
	require.NotNil(t, resp.GetNetworkMap(), "a serial change while away must force the full map")
	assert.Equal(t, serial, resp.GetNetworkMap().GetSerial(), "the full map must carry the current serial")
	waitForEntry(t, cache, peer, "the delivered map must be recorded", func(s uint64, ok bool) bool { return ok && s == serial })
	cancel()

	// A peer whose own meta changed gets its map computed again.
	peer.meta.Hostname = "renamed"
	resp, _, cancel = peer.sync()
	require.NotNil(t, resp.GetNetworkMap(), "a meta change must force the full map")
	waitForEntry(t, cache, peer, "the delivered map must be recorded", func(_ uint64, ok bool) bool { return ok })
	cancel()

	// A new engine after Login always gets its full map.
	peer.login()
	resp, _, cancel = peer.sync()
	require.NotNil(t, resp.GetNetworkMap(), "a Sync after Login must carry the full map")
	waitForEntry(t, cache, peer, "the delivered map must be recorded", func(_ uint64, ok bool) bool { return ok })
	cancel()

	// Clients that clear their posture checks on a response without a map always
	// get the full map.
	peer.meta.NetbirdVersion = "0.72.2"
	peer.login()
	resp, _, cancel = peer.sync()
	require.NotNil(t, resp.GetNetworkMap(), "the first Sync after Login must carry the full map")
	waitForEntry(t, cache, peer, "the delivered map must be recorded", func(_ uint64, ok bool) bool { return ok })
	cancel()
	resp, _, cancel = peer.sync()
	require.NotNil(t, resp.GetNetworkMap(), "an old client must never get a response without a map")
	cancel()
}

// invalidPeerValidator fails integrated validation for every peer.
type invalidPeerValidator struct {
	MockIntegratedValidator
}

func (invalidPeerValidator) IsNotValidPeer(context.Context, string, *nbpeer.Peer, []string, *types.ExtraSettings) (bool, bool, error) {
	return true, false, nil
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
