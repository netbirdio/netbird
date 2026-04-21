package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/protobuf/proto" //nolint:staticcheck // matches the generator
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/encryption"
	mgmtProto "github.com/netbirdio/netbird/shared/management/proto"
)

// sendWireFixture replays a frozen SyncRequest wire fixture as `peerKey` and
// returns the decoded first SyncResponse plus a cancel function. The caller
// must invoke cancel() so the server releases per-peer routines.
func sendWireFixture(t *testing.T, client mgmtProto.ManagementServiceClient, serverKey, peerKey wgtypes.Key, fixturePath string) (*mgmtProto.SyncResponse, context.CancelFunc) {
	t.Helper()

	raw, err := os.ReadFile(fixturePath)
	require.NoError(t, err, "read fixture %s", fixturePath)

	req := &mgmtProto.SyncRequest{}
	require.NoError(t, proto.Unmarshal(raw, req), "decode fixture %s as SyncRequest", fixturePath)

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

func TestSync_WireFixture_LegacyClients_AlwaysReceiveFullMap(t *testing.T) {
	skipOnWindows(t)
	cases := []struct {
		name    string
		fixture string
	}{
		{"v0.20.0 empty SyncRequest", "testdata/sync_request_wire/v0_20_0.bin"},
		{"v0.40.0 SyncRequest with Meta", "testdata/sync_request_wire/v0_40_0.bin"},
		{"v0.60.0 SyncRequest with Meta", "testdata/sync_request_wire/v0_60_0.bin"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
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

			abs, err := filepath.Abs(tc.fixture)
			require.NoError(t, err)
			resp, cancel := sendWireFixture(t, client, *serverKey, *keys[0], abs)
			defer cancel()

			require.NotNil(t, resp.NetworkMap, "legacy client first Sync must deliver a full NetworkMap")
			require.NotNil(t, resp.NetbirdConfig, "legacy client first Sync must include NetbirdConfig")
		})
	}
}

func TestSync_WireFixture_LegacyClient_ReconnectStillGetsFullMap(t *testing.T) {
	// v0.40.x clients call GrpcClient.GetNetworkMap on every OS during
	// readInitialSettings — they error on nil NetworkMap. Without extra opt-in
	// signalling there is no way for the server to know this is a GetNetworkMap
	// call rather than a main Sync, so the server's fast path would break them
	// on reconnect. This test pins the currently accepted tradeoff: a legacy
	// v0.40 client gets a full map on the first Sync but a reconnect with an
	// unchanged metaHash hits the primed cache and goes through the fast path.
	// When a future proto opt-in lets the server distinguish these clients,
	// this assertion must be tightened to require.NotNil(second.NetworkMap).
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

	abs, err := filepath.Abs("testdata/sync_request_wire/v0_40_0.bin")
	require.NoError(t, err)

	first, cancel1 := sendWireFixture(t, client, *serverKey, *keys[0], abs)
	require.NotNil(t, first.NetworkMap, "first legacy sync receives full map and primes cache")
	cancel1()
	waitForPeerDisconnect(t, am, keys[0].PublicKey().String())

	second, cancel2 := sendWireFixture(t, client, *serverKey, *keys[0], abs)
	defer cancel2()
	require.Nil(t, second.NetworkMap, "documented legacy-reconnect tradeoff: warm cache entry causes fast path; update when proto opt-in lands")
	require.NotNil(t, second.NetbirdConfig, "fast path still delivers NetbirdConfig")
}

func TestSync_WireFixture_AndroidReconnect_NeverSkips(t *testing.T) {
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

	abs, err := filepath.Abs("testdata/sync_request_wire/android_current.bin")
	require.NoError(t, err)

	first, cancel1 := sendWireFixture(t, client, *serverKey, *keys[0], abs)
	require.NotNil(t, first.NetworkMap, "android first sync must deliver a full map")
	cancel1()
	waitForPeerDisconnect(t, am, keys[0].PublicKey().String())

	second, cancel2 := sendWireFixture(t, client, *serverKey, *keys[0], abs)
	defer cancel2()
	require.NotNil(t, second.NetworkMap, "android reconnects must never take the fast path even with a primed cache")
}

func TestSync_WireFixture_ModernClientReconnect_TakesFastPath(t *testing.T) {
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

	abs, err := filepath.Abs("testdata/sync_request_wire/current.bin")
	require.NoError(t, err)

	first, cancel1 := sendWireFixture(t, client, *serverKey, *keys[0], abs)
	require.NotNil(t, first.NetworkMap, "modern first sync primes cache")
	cancel1()
	waitForPeerDisconnect(t, am, keys[0].PublicKey().String())

	second, cancel2 := sendWireFixture(t, client, *serverKey, *keys[0], abs)
	defer cancel2()
	require.Nil(t, second.NetworkMap, "modern reconnect with unchanged state must skip the NetworkMap")
	require.NotNil(t, second.NetbirdConfig, "fast path still delivers NetbirdConfig")
}
