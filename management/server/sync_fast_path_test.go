package server

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/encryption"
	"github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/store"
	mgmtProto "github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/util"
)

// skipOnWindows skips the calling test on Windows. The in-process gRPC
// harness uses Unix socket / path conventions that do not cleanly map to
// Windows.
func skipOnWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows; harness uses unix path conventions")
	}
}

func fastPathTestConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		Datadir: t.TempDir(),
		Stuns: []*config.Host{{
			Proto: "udp",
			URI:   "stun:stun.example:3478",
		}},
		TURNConfig: &config.TURNConfig{
			TimeBasedCredentials: true,
			CredentialsTTL:       util.Duration{Duration: time.Hour},
			Secret:               "turn-secret",
			Turns: []*config.Host{{
				Proto: "udp",
				URI:   "turn:turn.example:3478",
			}},
		},
		Relay: &config.Relay{
			Addresses:      []string{"rel.example:443"},
			CredentialsTTL: util.Duration{Duration: time.Hour},
			Secret:         "relay-secret",
		},
		Signal: &config.Host{
			Proto: "http",
			URI:   "signal.example:10000",
		},
		HttpConfig: nil,
	}
}

// openSync opens a Sync stream with the given meta and returns the decoded first
// SyncResponse plus a cancel function. The caller must call cancel() to release
// server-side routines before opening a new stream for the same peer.
func openSync(t *testing.T, client mgmtProto.ManagementServiceClient, serverKey, peerKey wgtypes.Key, meta *mgmtProto.PeerSystemMeta) (*mgmtProto.SyncResponse, context.CancelFunc) {
	t.Helper()

	req := &mgmtProto.SyncRequest{Meta: meta}
	body, err := encryption.EncryptMessage(serverKey, peerKey, req)
	require.NoError(t, err, "encrypt sync request")

	ctx, cancel := context.WithCancel(context.Background())
	stream, err := client.Sync(ctx, &mgmtProto.EncryptedMessage{
		WgPubKey: peerKey.PublicKey().String(),
		Body:     body,
	})
	require.NoError(t, err, "open sync stream")

	enc := &mgmtProto.EncryptedMessage{}
	require.NoError(t, stream.RecvMsg(enc), "receive first sync response")

	resp := &mgmtProto.SyncResponse{}
	require.NoError(t, encryption.DecryptMessage(serverKey, peerKey, enc.Body, resp), "decrypt sync response")

	return resp, cancel
}

// waitForPeerDisconnect polls until the account manager reports the peer as
// disconnected (Status.Connected == false), which happens once the server's
// handleUpdates goroutine has run cancelPeerRoutines for the cancelled
// stream. The deadline is bounded so a stuck server fails the test rather
// than hanging. Replaces the former fixed 50ms sleep which was CI-flaky
// under load or with the race detector on.
func waitForPeerDisconnect(t *testing.T, am *DefaultAccountManager, peerPubKey string) {
	t.Helper()
	require.Eventually(t, func() bool {
		peer, err := am.Store.GetPeerByPeerPubKey(context.Background(), store.LockingStrengthNone, peerPubKey)
		if err != nil {
			return false
		}
		return !peer.Status.Connected
	}, 2*time.Second, 10*time.Millisecond, "peer %s should be marked disconnected after stream cancel", peerPubKey)
}

func baseLinuxMeta() *mgmtProto.PeerSystemMeta {
	return &mgmtProto.PeerSystemMeta{
		Hostname:       "linux-host",
		GoOS:           "linux",
		OS:             "linux",
		Platform:       "x86_64",
		Kernel:         "5.15.0",
		NetbirdVersion: "0.70.0",
	}
}

func androidMeta() *mgmtProto.PeerSystemMeta {
	return &mgmtProto.PeerSystemMeta{
		Hostname:       "android-host",
		GoOS:           "android",
		OS:             "android",
		Platform:       "arm64",
		Kernel:         "4.19",
		NetbirdVersion: "0.70.0",
	}
}

func TestSyncFastPath_FirstSync_SendsFullMap(t *testing.T) {
	skipOnWindows(t)
	mgmtServer, _, addr, cleanup, err := startManagementForTest(t, "testdata/store_with_expired_peers.sql", fastPathTestConfig(t))
	require.NoError(t, err)
	defer cleanup()
	defer mgmtServer.GracefulStop()

	client, conn, err := createRawClient(addr)
	require.NoError(t, err)
	defer conn.Close()

	keys, err := registerPeers(1, client)
	require.NoError(t, err)
	serverKey, err := getServerKey(client)
	require.NoError(t, err)

	resp, cancel := openSync(t, client, *serverKey, *keys[0], baseLinuxMeta())
	defer cancel()

	require.NotNil(t, resp.NetworkMap, "first sync for a fresh peer must deliver a full NetworkMap")
	assert.NotNil(t, resp.NetbirdConfig, "NetbirdConfig must accompany the full map")
}

func TestSyncFastPath_SecondSync_MatchingSerial_SkipsMap(t *testing.T) {
	skipOnWindows(t)
	mgmtServer, am, addr, cleanup, err := startManagementForTest(t, "testdata/store_with_expired_peers.sql", fastPathTestConfig(t))
	require.NoError(t, err)
	defer cleanup()
	defer mgmtServer.GracefulStop()

	client, conn, err := createRawClient(addr)
	require.NoError(t, err)
	defer conn.Close()

	keys, err := registerPeers(1, client)
	require.NoError(t, err)
	serverKey, err := getServerKey(client)
	require.NoError(t, err)

	first, cancel1 := openSync(t, client, *serverKey, *keys[0], baseLinuxMeta())
	require.NotNil(t, first.NetworkMap, "first sync primes cache with a full map")
	cancel1()
	waitForPeerDisconnect(t, am, keys[0].PublicKey().String())

	second, cancel2 := openSync(t, client, *serverKey, *keys[0], baseLinuxMeta())
	defer cancel2()

	assert.Nil(t, second.NetworkMap, "second sync with unchanged state must omit NetworkMap")
	require.NotNil(t, second.NetbirdConfig, "fast path must still deliver NetbirdConfig")
	assert.NotEmpty(t, second.NetbirdConfig.Turns, "time-based TURN credentials must be refreshed on fast path")
	require.NotNil(t, second.NetbirdConfig.Relay, "relay config must be present on fast path")
	assert.NotEmpty(t, second.NetbirdConfig.Relay.TokenPayload, "relay token must be refreshed on fast path")
}

func TestSyncFastPath_AndroidNeverSkips(t *testing.T) {
	skipOnWindows(t)
	mgmtServer, am, addr, cleanup, err := startManagementForTest(t, "testdata/store_with_expired_peers.sql", fastPathTestConfig(t))
	require.NoError(t, err)
	defer cleanup()
	defer mgmtServer.GracefulStop()

	client, conn, err := createRawClient(addr)
	require.NoError(t, err)
	defer conn.Close()

	keys, err := registerPeers(1, client)
	require.NoError(t, err)
	serverKey, err := getServerKey(client)
	require.NoError(t, err)

	first, cancel1 := openSync(t, client, *serverKey, *keys[0], androidMeta())
	require.NotNil(t, first.NetworkMap, "android first sync must deliver a full map")
	cancel1()
	waitForPeerDisconnect(t, am, keys[0].PublicKey().String())

	second, cancel2 := openSync(t, client, *serverKey, *keys[0], androidMeta())
	defer cancel2()

	require.NotNil(t, second.NetworkMap, "android reconnects must never take the fast path")
}

func TestSyncFastPath_MetaChanged_SendsFullMap(t *testing.T) {
	skipOnWindows(t)
	mgmtServer, am, addr, cleanup, err := startManagementForTest(t, "testdata/store_with_expired_peers.sql", fastPathTestConfig(t))
	require.NoError(t, err)
	defer cleanup()
	defer mgmtServer.GracefulStop()

	client, conn, err := createRawClient(addr)
	require.NoError(t, err)
	defer conn.Close()

	keys, err := registerPeers(1, client)
	require.NoError(t, err)
	serverKey, err := getServerKey(client)
	require.NoError(t, err)

	first, cancel1 := openSync(t, client, *serverKey, *keys[0], baseLinuxMeta())
	require.NotNil(t, first.NetworkMap, "first sync primes cache")
	cancel1()
	waitForPeerDisconnect(t, am, keys[0].PublicKey().String())

	changed := baseLinuxMeta()
	changed.Hostname = "linux-host-renamed"
	second, cancel2 := openSync(t, client, *serverKey, *keys[0], changed)
	defer cancel2()

	require.NotNil(t, second.NetworkMap, "meta change must force a full map even when serial matches")
}

func TestSyncFastPath_LoginInvalidatesCache(t *testing.T) {
	skipOnWindows(t)
	mgmtServer, am, addr, cleanup, err := startManagementForTest(t, "testdata/store_with_expired_peers.sql", fastPathTestConfig(t))
	require.NoError(t, err)
	defer cleanup()
	defer mgmtServer.GracefulStop()

	client, conn, err := createRawClient(addr)
	require.NoError(t, err)
	defer conn.Close()

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	_, err = loginPeerWithValidSetupKey(key, client)
	require.NoError(t, err, "initial login must succeed")

	serverKey, err := getServerKey(client)
	require.NoError(t, err)

	first, cancel1 := openSync(t, client, *serverKey, key, baseLinuxMeta())
	require.NotNil(t, first.NetworkMap, "first sync primes cache")
	cancel1()
	waitForPeerDisconnect(t, am, key.PublicKey().String())

	// A subsequent login (e.g. SSH key rotation, re-auth) must clear the cache.
	_, err = loginPeerWithValidSetupKey(key, client)
	require.NoError(t, err, "second login must succeed")

	second, cancel2 := openSync(t, client, *serverKey, key, baseLinuxMeta())
	defer cancel2()
	require.NotNil(t, second.NetworkMap, "Login must invalidate the cache so the next Sync delivers a full map")
}

func TestSyncFastPath_OtherPeerRegistered_ForcesFullMap(t *testing.T) {
	skipOnWindows(t)
	mgmtServer, am, addr, cleanup, err := startManagementForTest(t, "testdata/store_with_expired_peers.sql", fastPathTestConfig(t))
	require.NoError(t, err)
	defer cleanup()
	defer mgmtServer.GracefulStop()

	client, conn, err := createRawClient(addr)
	require.NoError(t, err)
	defer conn.Close()

	keys, err := registerPeers(1, client)
	require.NoError(t, err)
	serverKey, err := getServerKey(client)
	require.NoError(t, err)

	first, cancel1 := openSync(t, client, *serverKey, *keys[0], baseLinuxMeta())
	require.NotNil(t, first.NetworkMap, "first sync primes cache at serial N")
	cancel1()
	waitForPeerDisconnect(t, am, keys[0].PublicKey().String())

	// Registering another peer bumps the account serial via IncrementNetworkSerial.
	_, err = registerPeers(1, client)
	require.NoError(t, err)

	second, cancel2 := openSync(t, client, *serverKey, *keys[0], baseLinuxMeta())
	defer cancel2()
	require.NotNil(t, second.NetworkMap, "serial advance must force a full map even if meta is unchanged")
}
