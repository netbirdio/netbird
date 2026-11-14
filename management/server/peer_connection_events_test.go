package server

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/management/server/activity"
	activitystore "github.com/netbirdio/netbird/management/server/activity/store"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/util/crypt"
)

func TestPeerConnectionHistory(t *testing.T) {
	manager, accountID, peer := newPeerConnectionTestPeer(t)
	ctx := context.Background()
	session := time.Now().UTC().UnixNano()
	_, _, _, _, err := manager.SyncAndMarkPeer(ctx, accountID, peer.Key, peer.Meta,
		net.ParseIP("::ffff:203.0.113.24"), time.Unix(0, session), nil)
	require.NoError(t, err)
	// Neither a duplicate connect nor an old stream ending may add a history entry.
	require.NoError(t, manager.MarkPeerConnected(ctx, peer.Key, accountID, session, nil))
	require.NoError(t, manager.MarkPeerDisconnected(ctx, peer.Key, accountID, session-1))
	require.NoError(t, manager.MarkPeerDisconnected(ctx, peer.Key, accountID, session))
	require.NoError(t, manager.MarkPeerDisconnected(ctx, peer.Key, accountID, session))

	waitForPeerConnectionEvents(t, manager, accountID, peer.ID, 2)

	// A subsequent address update must not rewrite the source IP in older events.
	current, err := manager.Store.GetPeerByID(ctx, store.LockingStrengthNone, accountID, peer.ID)
	require.NoError(t, err)
	current.Location.ConnectionIP = net.ParseIP("192.0.2.99")
	require.NoError(t, manager.Store.SavePeer(ctx, accountID, current))
	_, _, _, _, err = manager.SyncAndMarkPeer(ctx, accountID, peer.Key, peer.Meta,
		net.ParseIP("::ffff:198.51.100.12"), time.Unix(0, session+2), nil)
	require.NoError(t, err)
	waitForPeerConnectionEvents(t, manager, accountID, peer.ID, 3)

	history, err := readPeerConnectionEvents(ctx, manager, accountID, peer.ID)
	require.NoError(t, err)
	byCode := make(map[activity.Activity][]*activity.Event)
	for _, event := range history {
		byCode[event.Activity] = append(byCode[event.Activity], event)
		assert.Equal(t, activity.SystemInitiator, event.InitiatorID, "connections are system events")
		assert.Equal(t, "history-peer", event.Meta["name"], "snapshot the peer name")
		assert.False(t, event.Timestamp.IsZero(), "events must have an observation timestamp")
	}
	require.Len(t, byCode[activity.PeerConnected], 2, "one event per accepted session")
	require.Len(t, byCode[activity.PeerDisconnected], 1, "one event for the matching disconnect")
	assert.NotContains(t, byCode[activity.PeerDisconnected][0].Meta, "location_connection_ip", "a disconnect has no observed source IP")
	assert.ElementsMatch(t, []any{"203.0.113.24", "198.51.100.12"}, []any{
		byCode[activity.PeerConnected][0].Meta["location_connection_ip"], byCode[activity.PeerConnected][1].Meta["location_connection_ip"],
	}, "retain the source IP of each connection")
	visibleEvents, err := manager.GetEvents(ctx, accountID, userID)
	require.NoError(t, err)
	assert.Subset(t, visibleEvents, history, "the authorized activity feed must return the persisted history")

	t.Setenv("NB_EVENT_ACTIVITY_LOG_ENABLED", "false")
	require.NoError(t, manager.MarkPeerDisconnected(ctx, peer.Key, accountID, session+2))
	events, err := readPeerConnectionEvents(ctx, manager, accountID, peer.ID)
	require.NoError(t, err)
	assert.Len(t, events, 3, "disabled activity logging must not add connection events")
}

func TestPeerConnectionSourceIPFromSync(t *testing.T) {
	manager, accountID, peer := newPeerConnectionTestPeer(t)
	require.Nil(t, manager.geo, "source-IP recording must work with geolocation disabled")
	ctx := context.Background()
	for i, tc := range []struct {
		name string
		ip   net.IP
		want string
	}{
		{name: "IPv4", ip: net.ParseIP("203.0.113.24").To4(), want: "203.0.113.24"},
		{name: "mapped IPv4", ip: net.ParseIP("::ffff:203.0.113.25"), want: "203.0.113.25"},
		{name: "IPv6", ip: net.ParseIP("2001:db8::24"), want: "2001:db8::24"},
		{name: "unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, _, err := manager.SyncAndMarkPeer(ctx, accountID, peer.Key, peer.Meta,
				tc.ip, time.Now().UTC(), nil)
			require.NoError(t, err)
			waitForPeerConnectionEvents(t, manager, accountID, peer.ID, i+1)
			events, err := readPeerConnectionEvents(ctx, manager, accountID, peer.ID)
			require.NoError(t, err)
			event := events[len(events)-1]
			assert.Equal(t, "peer.connect", event.Activity.StringCode(), "expose the public connection event code")
			if tc.want == "" {
				assert.NotContains(t, event.Meta, "location_connection_ip", "do not substitute the stale cached address")
				return
			}
			assert.Equal(t, tc.want, event.Meta["location_connection_ip"], "record the stream address independently of cached geolocation")
			assert.NotContains(t, event.Meta, "location_country_code", "no country without a geo lookup")
			assert.NotContains(t, event.Meta, "location_city_name", "no city without a geo lookup")
		})
	}
}

func newPeerConnectionTestPeer(t *testing.T) (*DefaultAccountManager, string, *nbpeer.Peer) {
	t.Helper()
	t.Setenv("NB_EVENT_ACTIVITY_LOG_ENABLED", "true")
	t.Setenv("NB_ACTIVITY_EVENT_STORE_ENGINE", "sqlite")
	ctx := context.Background()
	manager, _, err := createManager(t)
	require.NoError(t, err)
	encryptionKey, err := crypt.GenerateKey()
	require.NoError(t, err)
	eventStore, err := activitystore.NewSqlStore(ctx, t.TempDir(), encryptionKey)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, eventStore.Close(ctx)) })
	manager.eventStore = eventStore
	accountID, err := manager.GetAccountIDByUserID(ctx, auth.UserAuth{UserId: userID})
	require.NoError(t, err)
	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	peer, _, _, _, err := manager.AddPeer(ctx, "", "", userID, &nbpeer.Peer{
		Key: key.PublicKey().String(), Meta: nbpeer.PeerSystemMeta{Hostname: "history-peer"},
	}, false)
	require.NoError(t, err)
	peer.Location.ConnectionIP = net.ParseIP("192.0.2.99")
	require.NoError(t, manager.Store.SavePeer(ctx, accountID, peer))
	return manager, accountID, peer
}

func readPeerConnectionEvents(ctx context.Context, manager *DefaultAccountManager, accountID, peerID string) ([]*activity.Event, error) {
	events, err := manager.eventStore.Get(ctx, accountID, 0, 10000, false)
	if err != nil {
		return nil, err
	}
	var history []*activity.Event
	for _, event := range events {
		if event.TargetID == peerID && (event.Activity == activity.PeerConnected || event.Activity == activity.PeerDisconnected) {
			history = append(history, event)
		}
	}
	return history, nil
}

func waitForPeerConnectionEvents(t *testing.T, manager *DefaultAccountManager, accountID, peerID string, count int) {
	t.Helper()
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		events, err := readPeerConnectionEvents(context.Background(), manager, accountID, peerID)
		require.NoError(collect, err)
		assert.Len(collect, events, count, "only accepted connection changes must be recorded")
	}, time.Second, time.Millisecond)
}

func TestPeerConnectionEventWithoutSourceIP(t *testing.T) {
	t.Setenv("NB_EVENT_ACTIVITY_LOG_ENABLED", "true")
	ctx := context.Background()
	eventStore := &activity.InMemoryEventStore{}
	manager := &DefaultAccountManager{eventStore: eventStore}
	peer := &nbpeer.Peer{ID: "peer-id", Name: "peer-without-address"}
	manager.storePeerConnectionEvent(ctx, "account-id", peer, activity.PeerConnected, netip.Addr{})
	require.Eventually(t, func() bool {
		events, err := eventStore.Get(ctx, "account-id", 0, 10, false)
		return err == nil && len(events) == 1
	}, time.Second, time.Millisecond, "record connections even when no source IP is available")
	events, err := eventStore.Get(ctx, "account-id", 0, 10, false)
	require.NoError(t, err)
	assert.NotContains(t, events[0].Meta, "location_connection_ip", "an unknown source IP must stay unknown")
	assert.Equal(t, "peer-without-address", events[0].Meta["name"], "retain the peer identity")
}

func TestPeerConnectionLocationFromSync(t *testing.T) {
	ctx := context.Background()

	t.Run("resolved for this connection", func(t *testing.T) {
		manager, accountID, peer := newPeerConnectionTestPeer(t)
		manager.geo = &fakeGeo{geoNameID: 2950159, isoCode: "DE", cityName: "Berlin"}

		// The sync resolves and saves the location for this address before the connect
		// is marked, so the event carries this connection's location, not the stale one.
		_, _, _, _, err := manager.SyncAndMarkPeer(ctx, accountID, peer.Key, peer.Meta,
			net.ParseIP("::ffff:203.0.113.24"), time.Now().UTC(), nil)
		require.NoError(t, err)
		waitForPeerConnectionEvents(t, manager, accountID, peer.ID, 1)

		events, err := readPeerConnectionEvents(ctx, manager, accountID, peer.ID)
		require.NoError(t, err)
		assert.Equal(t, "203.0.113.24", events[0].Meta["location_connection_ip"], "record the unmapped stream address")
		assert.Equal(t, "DE", events[0].Meta["location_country_code"], "record the country resolved for this connection")
		assert.Equal(t, "Berlin", events[0].Meta["location_city_name"], "record the city resolved for this connection")
	})

	t.Run("lookup fails", func(t *testing.T) {
		manager, accountID, peer := newPeerConnectionTestPeer(t)
		current, err := manager.Store.GetPeerByID(ctx, store.LockingStrengthNone, accountID, peer.ID)
		require.NoError(t, err)
		current.Location = nbpeer.Location{ConnectionIP: net.ParseIP("198.51.100.12"), CountryCode: "FR", CityName: "Paris"}
		require.NoError(t, manager.Store.SavePeer(ctx, accountID, current))
		manager.geo = &fakeGeo{err: errors.New("lookup failed")}

		// The stored Paris location belongs to an earlier address and must not be reused.
		_, _, _, _, err = manager.SyncAndMarkPeer(ctx, accountID, peer.Key, peer.Meta,
			net.ParseIP("203.0.113.24"), time.Now().UTC(), nil)
		require.NoError(t, err)
		waitForPeerConnectionEvents(t, manager, accountID, peer.ID, 1)

		events, err := readPeerConnectionEvents(ctx, manager, accountID, peer.ID)
		require.NoError(t, err)
		assert.Equal(t, "203.0.113.24", events[0].Meta["location_connection_ip"], "still record the stream address")
		assert.NotContains(t, events[0].Meta, "location_country_code", "never attach the previous connection's country")
		assert.NotContains(t, events[0].Meta, "location_city_name", "never attach the previous connection's city")
	})
}

func TestPeerConnectionEventLocation(t *testing.T) {
	berlin := func(ip string) nbpeer.Location {
		return nbpeer.Location{ConnectionIP: net.ParseIP(ip), CountryCode: "DE", CityName: "Berlin"}
	}
	for _, tc := range []struct {
		name         string
		location     nbpeer.Location
		code         activity.Activity
		sourceIP     netip.Addr
		wantIP       string
		wantLocation bool
	}{
		{
			name:     "location resolved for the source IP",
			location: berlin("203.0.113.24"), code: activity.PeerConnected,
			sourceIP: netip.MustParseAddr("203.0.113.24"), wantIP: "203.0.113.24", wantLocation: true,
		},
		{
			// net.ParseIP stores IPv4 in its 16-byte form, which must still match.
			name:     "stored IPv4 in 16-byte form",
			location: berlin("::ffff:203.0.113.24"), code: activity.PeerConnected,
			sourceIP: netip.MustParseAddr("::ffff:203.0.113.24"), wantIP: "203.0.113.24", wantLocation: true,
		},
		{
			name:     "IPv6 source",
			location: berlin("2001:db8::24"), code: activity.PeerConnected,
			sourceIP: netip.MustParseAddr("2001:db8::24"), wantIP: "2001:db8::24", wantLocation: true,
		},
		{
			name:     "location from an earlier connection",
			location: berlin("198.51.100.12"), code: activity.PeerConnected,
			sourceIP: netip.MustParseAddr("203.0.113.24"), wantIP: "203.0.113.24",
		},
		{
			name:     "no stored location",
			code:     activity.PeerConnected,
			sourceIP: netip.MustParseAddr("203.0.113.24"), wantIP: "203.0.113.24",
		},
		{
			name:     "disconnect",
			location: berlin("203.0.113.24"), code: activity.PeerDisconnected,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("NB_EVENT_ACTIVITY_LOG_ENABLED", "true")
			ctx := context.Background()
			eventStore := &activity.InMemoryEventStore{}
			manager := &DefaultAccountManager{eventStore: eventStore}
			peer := &nbpeer.Peer{ID: "peer-id", Name: "located-peer", Location: tc.location}

			manager.storePeerConnectionEvent(ctx, "account-id", peer, tc.code, tc.sourceIP)
			var events []*activity.Event
			require.Eventually(t, func() bool {
				var err error
				events, err = eventStore.Get(ctx, "account-id", 0, 10, false)
				return err == nil && len(events) == 1
			}, time.Second, time.Millisecond, "the event must be stored")

			meta := events[0].Meta
			if tc.wantIP == "" {
				assert.NotContains(t, meta, "location_connection_ip", "no source IP without an observed address")
			} else {
				assert.Equal(t, tc.wantIP, meta["location_connection_ip"], "always record the observed source IP")
			}
			if !tc.wantLocation {
				assert.NotContains(t, meta, "location_country_code", "never attach a location from another address")
				assert.NotContains(t, meta, "location_city_name", "never attach a location from another address")
				return
			}
			assert.Equal(t, "DE", meta["location_country_code"], "attach the matching country")
			assert.Equal(t, "Berlin", meta["location_city_name"], "attach the matching city")
		})
	}
}
