package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/management/server/activity"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/shared/auth"
)

func addSessionEventTestPeer(t *testing.T, manager *DefaultAccountManager) (peerPubKey, accountID, peerID string) {
	t.Helper()

	accountID, err := manager.GetAccountIDByUserID(context.Background(), auth.UserAuth{UserId: userID})
	require.NoError(t, err, "unable to create an account")

	key, err := wgtypes.GenerateKey()
	require.NoError(t, err, "unable to generate WireGuard key")
	peerPubKey = key.PublicKey().String()

	peer, _, _, _, err := manager.AddPeer(context.Background(), "", "", userID, &nbpeer.Peer{
		Key:  peerPubKey,
		Meta: nbpeer.PeerSystemMeta{Hostname: "session-event-peer"},
	}, false)
	require.NoError(t, err, "unable to add peer")
	return peerPubKey, accountID, peer.ID
}

func eventsByActivity(t *testing.T, manager *DefaultAccountManager, accountID string, code activity.Activity) []*activity.Event {
	t.Helper()

	events, err := manager.eventStore.Get(context.Background(), accountID, 0, 100, false)
	require.NoError(t, err)
	var matched []*activity.Event
	for _, e := range events {
		if e.Activity == code {
			matched = append(matched, e)
		}
	}
	return matched
}

func TestDefaultAccountManager_MarkPeerConnected_StoresEvent(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)
	peerPubKey, accountID, peerID := addSessionEventTestPeer(t, manager)

	require.NoError(t, manager.MarkPeerConnected(context.Background(), peerPubKey, accountID, time.Now().UnixNano(), nil))

	require.Eventually(t, func() bool {
		return len(eventsByActivity(t, manager, accountID, activity.PeerConnected)) == 1
	}, 5*time.Second, 10*time.Millisecond, "connect should store one peer.connect event")

	event := eventsByActivity(t, manager, accountID, activity.PeerConnected)[0]
	assert.Equal(t, peerID, event.TargetID)
	assert.Equal(t, userID, event.InitiatorID, "a user-owned peer is attributed to its owner")
	for _, key := range []string{"name", "fqdn", "ip", "location_connection_ip"} {
		assert.Contains(t, event.Meta, key)
	}
	assert.Equal(t, "session-event-peer", event.Meta["name"])
	assert.NotContains(t, event.Meta, "session_duration")
}

func TestDefaultAccountManager_MarkPeerConnected_StaleSessionStoresNoEvent(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)
	peerPubKey, accountID, _ := addSessionEventTestPeer(t, manager)

	now := time.Now()
	require.NoError(t, manager.MarkPeerConnected(context.Background(), peerPubKey, accountID, now.UnixNano(), nil))
	require.Eventually(t, func() bool {
		return len(eventsByActivity(t, manager, accountID, activity.PeerConnected)) == 1
	}, 5*time.Second, 10*time.Millisecond)

	// An older session loses to the stored one and must not emit.
	require.NoError(t, manager.MarkPeerConnected(context.Background(), peerPubKey, accountID, now.Add(-time.Minute).UnixNano(), nil))

	assert.Never(t, func() bool {
		return len(eventsByActivity(t, manager, accountID, activity.PeerConnected)) > 1
	}, 300*time.Millisecond, 20*time.Millisecond, "stale connect must not store an event")
}

func TestDefaultAccountManager_MarkPeerDisconnected_StoresEvent(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)
	peerPubKey, accountID, peerID := addSessionEventTestPeer(t, manager)

	sessionStart := time.Now().Add(-90 * time.Second).UnixNano()
	require.NoError(t, manager.MarkPeerConnected(context.Background(), peerPubKey, accountID, sessionStart, nil))
	require.NoError(t, manager.MarkPeerDisconnected(context.Background(), peerPubKey, accountID, sessionStart))

	require.Eventually(t, func() bool {
		return len(eventsByActivity(t, manager, accountID, activity.PeerDisconnected)) == 1
	}, 5*time.Second, 10*time.Millisecond, "disconnect should store one peer.disconnect event")

	event := eventsByActivity(t, manager, accountID, activity.PeerDisconnected)[0]
	assert.Equal(t, peerID, event.TargetID)
	assert.Equal(t, userID, event.InitiatorID)
	assert.Contains(t, event.Meta, "fqdn")
	duration, ok := event.Meta["session_duration"].(int64)
	require.True(t, ok, "session_duration should be whole seconds, got %T", event.Meta["session_duration"])
	assert.GreaterOrEqual(t, duration, int64(90))
	assert.Less(t, duration, int64(120))
}

func TestDefaultAccountManager_MarkPeerDisconnected_StaleSessionStoresNoEvent(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)
	peerPubKey, accountID, _ := addSessionEventTestPeer(t, manager)

	sessionStart := time.Now().UnixNano()
	require.NoError(t, manager.MarkPeerConnected(context.Background(), peerPubKey, accountID, sessionStart, nil))

	// A disconnect from a session that no longer owns the peer is ignored.
	require.NoError(t, manager.MarkPeerDisconnected(context.Background(), peerPubKey, accountID, sessionStart-1))

	assert.Never(t, func() bool {
		return len(eventsByActivity(t, manager, accountID, activity.PeerDisconnected)) > 0
	}, 300*time.Millisecond, 20*time.Millisecond, "stale disconnect must not store an event")
}
