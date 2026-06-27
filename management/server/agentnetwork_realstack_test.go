package server

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	networkmap "github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork"
	agenttypes "github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	nbproto "github.com/netbirdio/netbird/shared/management/proto"
)

// TestAgentNetwork_ProviderCRUD_FansOutToProxyAndClientPeers is the no-mock
// integration test for the live propagation path: a provider/policy mutation
// through the real agentnetwork.Manager triggers the real
// DefaultAccountManager.UpdateAccountPeers, which runs the real network-map
// controller (including AN-2b's injectAllProxyPolicies), and a network map is
// computed and fanned out to BOTH the embedded proxy peer and the client peer.
//
// Unlike the synthesizer/reconcile unit tests, nothing here is mocked: real
// SQLite store, real account manager + network-map controller, real
// agentnetwork manager, real peer update channels. The client peer's delivered
// map is asserted to actually carry the synth DNS surface, and provider
// create/delete are exercised end to end.
func TestAgentNetwork_ProviderCRUD_FansOutToProxyAndClientPeers(t *testing.T) {
	am, updateManager, err := createManager(t)
	require.NoError(t, err, "createManager must succeed")
	ctx := context.Background()

	const (
		accountID    = "agent-net-acct-1"
		adminUserID  = "agent-net-admin-1"
		groupAID     = "agent-net-grp-A"
		clusterAddr  = "eu.proxy.netbird.io"
		clientKey    = "BhRPtynAAYRDy08+q4HTMsos8fs4plTP4NOSh7C1ry8="
		proxyPeerID  = "agent-net-proxy-peer-1"
		proxyPeerKey = "/yF0+vCfv+mRR5k0dca0TrGdO/oiNeAI58gToZm5NyI="
		proxyIP      = "100.64.0.99"
	)

	account := newAccountWithId(ctx, accountID, adminUserID, "agent-net.test", "", "", false)
	require.NoError(t, am.Store.SaveAccount(ctx, account), "SaveAccount must succeed")

	// Real client peer through the production AddPeer path.
	clientPeer := &nbpeer.Peer{
		Key:      clientKey,
		Name:     "agent-net-client",
		DNSLabel: "agent-net-client",
		Meta:     nbpeer.PeerSystemMeta{Hostname: "agent-net-client", GoOS: "linux", WtVersion: "development"},
	}
	addedClient, _, _, _, err := am.AddPeer(ctx, "", "", adminUserID, clientPeer, false)
	require.NoError(t, err, "AddPeer must add the client peer")

	// Inject a connected embedded proxy peer + put the client in the source group.
	account, err = am.Store.GetAccount(ctx, accountID)
	require.NoError(t, err)
	account.Peers[proxyPeerID] = &nbpeer.Peer{
		ID:        proxyPeerID,
		AccountID: accountID,
		Key:       proxyPeerKey,
		IP:        netip.MustParseAddr(proxyIP),
		Status:    &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now().UTC()},
		ProxyMeta: nbpeer.ProxyMeta{Embedded: true, Cluster: clusterAddr},
		DNSLabel:  "agent-net-proxy",
	}
	account.Groups[groupAID] = &types.Group{ID: groupAID, Name: "groupA", Peers: []string{addedClient.ID}}
	require.NoError(t, am.Store.SaveAccount(ctx, account), "SaveAccount must persist proxy peer + group")

	// Subscribe to BOTH peers' update channels — this is how we observe the
	// real fan-out.
	clientCh := updateManager.CreateChannel(ctx, addedClient.ID)
	proxyCh := updateManager.CreateChannel(ctx, proxyPeerID)
	t.Cleanup(func() {
		updateManager.CloseChannel(ctx, addedClient.ID)
		updateManager.CloseChannel(ctx, proxyPeerID)
	})
	drain(clientCh)
	drain(proxyCh)

	// Real agentnetwork manager wired to the real account manager. proxyController
	// is nil (no gRPC cluster fan-out here) — the reconcile still fires
	// UpdateAccountPeers, which is the path under test.
	agentMgr := agentnetwork.NewManager(am.Store, permissions.NewManager(am.Store), am, nil)

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

	policy, err := agentMgr.CreatePolicy(ctx, adminUserID, &agenttypes.Policy{
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

	// Both peers must receive a fan-out. The provider-create reconcile fires
	// before the policy exists (synth service then has no AccessGroups, so no
	// zone), and the async update buffer can collapse/reorder updates — so we
	// poll until the client's delivered map actually carries the synth record.
	rdata := awaitZoneRData(clientCh, clusterAddr, fqdn, true)
	assert.Equal(t, proxyIP, rdata,
		"client peer's delivered network map must contain the synth DNS record pointing at the embedded proxy peer")
	require.True(t, awaitUpdate(proxyCh), "embedded proxy peer must also receive a netmap update after create")

	// UPDATE the provider — a new model on the existing service must still
	// reconcile and keep the private surface routable (the live MODIFIED path).
	provider.Models = append(provider.Models, agenttypes.ProviderModel{ID: "gpt-5.4-mini"})
	_, err = agentMgr.UpdateProvider(ctx, adminUserID, provider)
	require.NoError(t, err, "UpdateProvider must succeed")
	assert.Equal(t, proxyIP, awaitZoneRData(clientCh, clusterAddr, fqdn, true),
		"client peer must still resolve the synth record after the provider is updated")
	require.True(t, awaitUpdate(proxyCh), "embedded proxy peer must also receive a netmap update after update")

	// DELETE: detach the policy first (provider is in use), then drop the
	// provider. Both peers update again and the synth surface disappears.
	require.NoError(t, agentMgr.DeletePolicy(ctx, accountID, adminUserID, policy.ID), "DeletePolicy must succeed")
	require.NoError(t, agentMgr.DeleteProvider(ctx, accountID, adminUserID, provider.ID), "DeleteProvider must succeed")

	require.True(t, awaitUpdate(proxyCh), "embedded proxy peer must also receive a netmap update after delete")
	assert.Empty(t, awaitZoneRData(clientCh, clusterAddr, fqdn, false),
		"synth DNS record must be gone from the client's map after the provider is deleted")
}

// awaitZoneRData drains the channel for up to 8s. When wantPresent is true it
// returns as soon as the synth record appears (its RData). When false it drains
// to quiescence and returns the RData of the last delivered map (expected empty
// once the provider is gone), tolerating stale buffered updates that still
// carry the zone.
func awaitZoneRData(ch <-chan *networkmap.UpdateMessage, clusterAddr, fqdn string, wantPresent bool) string {
	deadline := time.After(8 * time.Second)
	last := ""
	for {
		select {
		case m := <-ch:
			if m == nil {
				continue
			}
			last = synthZoneRData(m.Update, clusterAddr, fqdn)
			if wantPresent && last != "" {
				return last
			}
		case <-time.After(750 * time.Millisecond):
			return last
		case <-deadline:
			return last
		}
	}
}

// awaitUpdate reports whether at least one update arrives within the window.
func awaitUpdate(ch <-chan *networkmap.UpdateMessage) bool {
	select {
	case m := <-ch:
		return m != nil
	case <-time.After(5 * time.Second):
		return false
	}
}

// drain empties any buffered updates (e.g. from AddPeer/SaveAccount) so the
// next observation reflects the operation under test.
func drain(ch <-chan *networkmap.UpdateMessage) {
	for {
		select {
		case <-ch:
		case <-time.After(200 * time.Millisecond):
			return
		}
	}
}

// synthZoneRData returns the RData of the synth A record (record name == fqdn)
// inside the cluster's custom zone, or "" when absent.
func synthZoneRData(sync *nbproto.SyncResponse, clusterAddr, fqdn string) string {
	if sync == nil {
		return ""
	}
	for _, zone := range sync.GetNetworkMap().GetDNSConfig().GetCustomZones() {
		if zone.GetDomain() != dns.Fqdn(clusterAddr) {
			continue
		}
		for _, rec := range zone.GetRecords() {
			if rec.GetName() == dns.Fqdn(fqdn) {
				return rec.GetRData()
			}
		}
	}
	return ""
}
