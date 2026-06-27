package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/peers"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork"
	agenttypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// TestAgentNetwork_ProxyRestart_PropagatesNewPeerAndDropsStale is the no-mock
// regression guard for the bug the user reported: restarting the proxy creates
// a fresh embedded peer with a NEW WireGuard public key (the proxy generates
// the keypair on every startup at proxy/internal/roundtrip/netbird.go:312).
// The PRIOR embedded peer record is never deleted on management, so the
// account accumulates a stale peer holding a stale CGNAT IP. Other peers
// in the account either keep routing to the dead IP, or — if synth DNS
// picks the wrong record — never see the new IP at all.
//
// What this test exercises (no mocks):
//   - real SQLite test store
//   - real DefaultAccountManager, network-map controller, peer-update channels
//   - real peers.Manager.CreateProxyPeer path (the very method the proxy
//     invokes over gRPC on every startup)
//   - real agentnetwork.Manager + synth chain so the client receives a
//     concrete DNS record that must point at the LATEST proxy peer.
//
// Pre-fix expected behavior (red): two embedded peers exist after the
// "restart"; the synth DNS record points at the stale one; the client
// receives an update reflecting the new peer but the old one lingers.
// Post-fix expected behavior (green): exactly one embedded peer exists
// after restart (with the new key) AND the client's network map carries
// the synth DNS pointing at that new peer's CGNAT IP.
func TestAgentNetwork_ProxyRestart_PropagatesNewPeerAndDropsStale(t *testing.T) {
	am, updateManager, err := createManager(t)
	require.NoError(t, err, "createManager must succeed")
	ctx := context.Background()

	const (
		accountID   = "an-restart-acct"
		adminUserID = "an-restart-admin"
		groupAID    = "an-restart-grp-A"
		clusterAddr = "eu.proxy.netbird.io"
		clientKey   = "BhRPtynAAYRDy08+q4HTMsos8fs4plTP4NOSh7C1ry8="
		// Two different proxy pubkeys — the "before" and "after" of a
		// proxy-process restart with fresh-keypair generation.
		proxyKey1 = "Aaaaa1aaaaYRDy08+q4HTMsos8fs4plTP4NOSh7C1ry8="
		proxyKey2 = "Bbbbb2bbbbYRDy08+q4HTMsos8fs4plTP4NOSh7C1ry8="
	)

	// --- Account scaffold ---
	account := newAccountWithId(ctx, accountID, adminUserID, "an-restart.test", "", "", false)
	require.NoError(t, am.Store.SaveAccount(ctx, account))

	clientPeer := &nbpeer.Peer{
		Key:      clientKey,
		Name:     "an-restart-client",
		DNSLabel: "an-restart-client",
		Meta:     nbpeer.PeerSystemMeta{Hostname: "an-restart-client", GoOS: "linux", WtVersion: "development"},
	}
	addedClient, _, _, _, err := am.AddPeer(ctx, "", "", adminUserID, clientPeer, false)
	require.NoError(t, err, "AddPeer for client must succeed")
	require.NoError(t, am.MarkPeerConnected(ctx, clientKey, accountID, time.Now().UnixNano(), &types.NetworkMap{}),
		"MarkPeerConnected for the client peer must succeed (affected-peer fan-out skips disconnected peers)")

	// Place the client in group A so the synth policy reaches it.
	account, err = am.Store.GetAccount(ctx, accountID)
	require.NoError(t, err)
	account.Groups[groupAID] = &types.Group{ID: groupAID, Name: "groupA", Peers: []string{addedClient.ID}}
	require.NoError(t, am.Store.SaveAccount(ctx, account), "SaveAccount must persist group A")

	// --- Real peers + agent-network managers ---
	permMgr := permissions.NewManager(am.Store)
	peersMgr := peers.NewManager(am.Store, permMgr)
	peersMgr.SetAccountManager(am)
	peersMgr.SetNetworkMapController(am.networkMapController)
	agentMgr := agentnetwork.NewManager(am.Store, permMgr, am, nil)

	// Subscribe BEFORE any state-mutating call so we don't lose the update
	// that contains the synth DNS record.
	clientCh := updateManager.CreateChannel(ctx, addedClient.ID)
	t.Cleanup(func() { updateManager.CloseChannel(ctx, addedClient.ID) })
	drain(clientCh)

	// --- First proxy startup: register peer key K1, then mark it
	// connected. In production the proxy follows CreateProxyPeer with the
	// regular sync stream which lands on MarkPeerConnected; the synth DNS
	// path filters out peers that aren't Connected (types/account.go:323),
	// so without this step no DNS record would be emitted.
	require.NoError(t, peersMgr.CreateProxyPeer(ctx, accountID, proxyKey1, clusterAddr),
		"first CreateProxyPeer (proxy startup) must succeed")

	peer1ID, err := am.Store.GetPeerIDByKey(ctx, store.LockingStrengthNone, proxyKey1)
	require.NoError(t, err, "proxy peer for K1 must be persisted after CreateProxyPeer")
	require.NotEmpty(t, peer1ID)

	require.NoError(t, am.MarkPeerConnected(ctx, proxyKey1, accountID, time.Now().UnixNano(), &types.NetworkMap{}),
		"MarkPeerConnected for K1 must succeed")

	account, err = am.Store.GetAccount(ctx, accountID)
	require.NoError(t, err)
	proxyIP1 := account.Peers[peer1ID].IP.String()
	require.NotEmpty(t, proxyIP1, "K1 must have an assigned overlay IP")

	// --- Provider + policy. CreateProvider / CreatePolicy trigger the
	// agentnetwork reconcile which runs UpdateAccountPeers; the resulting
	// NetworkMap delivered to the client carries the synth DNS record
	// pointing at K1's IP. ---
	provider, err := agentMgr.CreateProvider(ctx, adminUserID, &agenttypes.Provider{
		AccountID:   accountID,
		ProviderID:  "openai_api",
		Name:        "openai-test",
		UpstreamURL: "https://api.openai.com",
		APIKey:      "sk-test-key",
		Enabled:     true,
		Models:      []agenttypes.ProviderModel{{ID: "gpt-5.4"}},
	}, clusterAddr)
	require.NoError(t, err, "CreateProvider must succeed")

	_, err = agentMgr.CreatePolicy(ctx, adminUserID, &agenttypes.Policy{
		AccountID:              accountID,
		Name:                   "p1",
		Enabled:                true,
		SourceGroups:           []string{groupAID},
		DestinationProviderIDs: []string{provider.ID},
	})
	require.NoError(t, err, "CreatePolicy must succeed")

	settings, err := am.Store.GetAgentNetworkSettings(ctx, store.LockingStrengthNone, accountID)
	require.NoError(t, err)
	fqdn := settings.Endpoint()

	rdata1 := awaitZoneRData(clientCh, clusterAddr, fqdn, true)
	require.Equal(t, proxyIP1, rdata1,
		"client must receive a synth DNS record pointing at K1's overlay IP after the synth path runs")
	drain(clientCh)

	// --- Proxy restart: NEW keypair K2, same account, same cluster ---
	require.NoError(t, peersMgr.CreateProxyPeer(ctx, accountID, proxyKey2, clusterAddr),
		"second CreateProxyPeer (proxy restart with fresh keypair) must succeed")

	peer2ID, err := am.Store.GetPeerIDByKey(ctx, store.LockingStrengthNone, proxyKey2)
	require.NoError(t, err, "proxy peer for K2 must be persisted after restart")
	require.NotEmpty(t, peer2ID)

	require.NoError(t, am.MarkPeerConnected(ctx, proxyKey2, accountID, time.Now().UnixNano(), &types.NetworkMap{}),
		"MarkPeerConnected for K2 must succeed")

	// In production the agent's sync stream pulls a fresh NetworkMap as
	// part of its normal reconcile cadence; in this isolated test
	// MarkPeerConnected's affected-peer fan-out can race the channel-side
	// buffer in a way that swallows the synth-DNS-bearing update before
	// our await reads it. Trigger an explicit account-wide fan-out so the
	// assertion below tests what production actually delivers, not the
	// in-test buffer race.
	am.UpdateAccountPeers(ctx, accountID, types.UpdateReason{Resource: types.UpdateResourcePeer, Operation: types.UpdateOperationUpdate})

	account, err = am.Store.GetAccount(ctx, accountID)
	require.NoError(t, err)
	proxyIP2 := account.Peers[peer2ID].IP.String()
	require.NotEmpty(t, proxyIP2, "K2 must have an assigned overlay IP")
	require.NotEqual(t, proxyIP1, proxyIP2, "K2 must get a different overlay IP than K1 (sanity)")

	// CRITICAL ASSERTION 1: K1 must no longer be in the store. The SqlStore
	// returns ("", nil) for a missing key rather than NotFound, so assert
	// on the returned ID being empty.
	staleID, err := am.Store.GetPeerIDByKey(ctx, store.LockingStrengthNone, proxyKey1)
	require.NoError(t, err, "GetPeerIDByKey for a missing peer must not error")
	assert.Empty(t, staleID,
		"stale embedded proxy peer K1 must be removed when a new embedded peer registers for the same (account, cluster); pre-fix this assertion fails because management never cleans up the prior peer record")

	// CRITICAL ASSERTION 2: exactly one embedded proxy peer remains, and it
	// is K2.
	account, err = am.Store.GetAccount(ctx, accountID)
	require.NoError(t, err)
	embeddedKeys := []string{}
	for _, p := range account.Peers {
		if p.ProxyMeta.Embedded {
			embeddedKeys = append(embeddedKeys, p.Key)
		}
	}
	assert.Equal(t, []string{proxyKey2}, embeddedKeys,
		"after a proxy restart exactly one embedded proxy peer should remain — the one with the new key K2")

	// CRITICAL ASSERTION 3: the synth DNS record the client receives now
	// points at K2's IP, not K1's.
	rdata2 := awaitZoneRData(clientCh, clusterAddr, fqdn, true)
	assert.Equal(t, proxyIP2, rdata2,
		"after proxy restart, the client's synth DNS record must point at the NEW embedded peer's IP, not the stale K1 IP")
}
