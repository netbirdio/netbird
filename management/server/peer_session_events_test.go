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
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
)

// newSessionEventManager builds a manager with the startup grace window off, so events are
// recorded right away.
func newSessionEventManager(t *testing.T) *DefaultAccountManager {
	t.Helper()

	t.Setenv(EnvPeerSessionEventsStartupGrace, "0")
	manager, _, err := createManager(t)
	require.NoError(t, err)
	return manager
}

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
	manager := newSessionEventManager(t)
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
	manager := newSessionEventManager(t)
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
	manager := newSessionEventManager(t)
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
	manager := newSessionEventManager(t)
	peerPubKey, accountID, _ := addSessionEventTestPeer(t, manager)

	sessionStart := time.Now().UnixNano()
	require.NoError(t, manager.MarkPeerConnected(context.Background(), peerPubKey, accountID, sessionStart, nil))

	// A disconnect from a session that no longer owns the peer is ignored.
	require.NoError(t, manager.MarkPeerDisconnected(context.Background(), peerPubKey, accountID, sessionStart-1))

	assert.Never(t, func() bool {
		return len(eventsByActivity(t, manager, accountID, activity.PeerDisconnected)) > 0
	}, 300*time.Millisecond, 20*time.Millisecond, "stale disconnect must not store an event")
}

func TestDefaultAccountManager_SessionEvents_SetupKeyPeerIsSystemInitiated(t *testing.T) {
	manager := newSessionEventManager(t)
	_, accountID, _ := addSessionEventTestPeer(t, manager)

	setupKey, err := manager.CreateSetupKey(context.Background(), accountID, "session-key", types.SetupKeyReusable, time.Hour, nil, 10, userID, false, false)
	require.NoError(t, err)
	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	peerPubKey := key.PublicKey().String()
	peer, _, _, _, err := manager.AddPeer(context.Background(), "", setupKey.Key, "", &nbpeer.Peer{
		Key:  peerPubKey,
		Meta: nbpeer.PeerSystemMeta{Hostname: "setup-key-peer"},
	}, false)
	require.NoError(t, err)
	require.Empty(t, peer.UserID, "a setup-key peer has no owner")

	sessionStart := time.Now().Add(-time.Minute).UnixNano()
	require.NoError(t, manager.MarkPeerConnected(context.Background(), peerPubKey, accountID, sessionStart, nil))
	require.NoError(t, manager.MarkPeerDisconnected(context.Background(), peerPubKey, accountID, sessionStart))

	for _, code := range []activity.Activity{activity.PeerConnected, activity.PeerDisconnected} {
		require.Eventually(t, func() bool {
			return len(eventsByActivity(t, manager, accountID, code)) == 1
		}, 5*time.Second, 10*time.Millisecond, "%s should be stored", code.StringCode())
		assert.Equal(t, activity.SystemInitiator, eventsByActivity(t, manager, accountID, code)[0].InitiatorID,
			"%s of a setup-key peer is a system event", code.StringCode())
	}
}

func TestDefaultAccountManager_MarkPeerConnected_StartupGrace(t *testing.T) {
	t.Setenv(EnvPeerSessionEventsStartupGrace, "10m")
	manager, _, err := createManager(t)
	require.NoError(t, err)
	peerPubKey, accountID, _ := addSessionEventTestPeer(t, manager)

	require.NoError(t, manager.MarkPeerConnected(context.Background(), peerPubKey, accountID, time.Now().UnixNano(), nil))
	assert.Never(t, func() bool {
		return len(eventsByActivity(t, manager, accountID, activity.PeerConnected)) > 0
	}, 300*time.Millisecond, 20*time.Millisecond, "a connect inside the startup window stores no event")

	// Move the window's end into the past instead of waiting it out.
	manager.sessionEventsFrom = time.Now().Add(-time.Second)
	require.NoError(t, manager.MarkPeerConnected(context.Background(), peerPubKey, accountID, time.Now().UnixNano(), nil))
	require.Eventually(t, func() bool {
		return len(eventsByActivity(t, manager, accountID, activity.PeerConnected)) == 1
	}, 5*time.Second, 10*time.Millisecond, "a connect after the window stores an event")
}

func TestDefaultAccountManager_MarkPeerDisconnected_StartupGrace(t *testing.T) {
	t.Setenv(EnvPeerSessionEventsStartupGrace, "10m")
	manager, _, err := createManager(t)
	require.NoError(t, err)
	peerPubKey, accountID, _ := addSessionEventTestPeer(t, manager)

	sessionStart := time.Now().UnixNano()
	require.NoError(t, manager.MarkPeerConnected(context.Background(), peerPubKey, accountID, sessionStart, nil))
	require.NoError(t, manager.MarkPeerDisconnected(context.Background(), peerPubKey, accountID, sessionStart))

	assert.Never(t, func() bool {
		return len(eventsByActivity(t, manager, accountID, activity.PeerDisconnected)) > 0
	}, 300*time.Millisecond, 20*time.Millisecond, "a disconnect inside the startup window stores no event")
}

func TestDefaultAccountManager_MarkPeerDisconnected_DrainingStoresNoEvent(t *testing.T) {
	manager := newSessionEventManager(t)
	peerPubKey, accountID, _ := addSessionEventTestPeer(t, manager)

	sessionStart := time.Now().UnixNano()
	require.NoError(t, manager.MarkPeerConnected(context.Background(), peerPubKey, accountID, sessionStart, nil))
	require.Eventually(t, func() bool {
		return len(eventsByActivity(t, manager, accountID, activity.PeerConnected)) == 1
	}, 5*time.Second, 10*time.Millisecond)

	manager.StartDraining()
	require.NoError(t, manager.MarkPeerDisconnected(context.Background(), peerPubKey, accountID, sessionStart))

	assert.Never(t, func() bool {
		return len(eventsByActivity(t, manager, accountID, activity.PeerDisconnected)) > 0
	}, 300*time.Millisecond, 20*time.Millisecond, "a disconnect while draining stores no event")
	peer, err := manager.Store.GetPeerByPeerPubKey(context.Background(), store.LockingStrengthNone, peerPubKey)
	require.NoError(t, err)
	assert.False(t, peer.Status.Connected, "the disconnect itself is still written")
}

func TestPeerSessionEventsStartupGrace(t *testing.T) {
	tests := []struct {
		name  string
		value string
		set   bool
		want  time.Duration
	}{
		{name: "unset uses the default", want: 2 * time.Minute},
		{name: "empty uses the default", set: true, value: "", want: 2 * time.Minute},
		{name: "duration", set: true, value: "90s", want: 90 * time.Second},
		{name: "zero disables", set: true, value: "0", want: 0},
		{name: "invalid uses the default", set: true, value: "soon", want: 2 * time.Minute},
		{name: "negative uses the default", set: true, value: "-1m", want: 2 * time.Minute},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvPeerSessionEventsStartupGrace, "")
			if tc.set {
				t.Setenv(EnvPeerSessionEventsStartupGrace, tc.value)
			}
			assert.Equal(t, tc.want, peerSessionEventsStartupGrace())
		})
	}
}
