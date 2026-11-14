package server

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/activity"
	nbcontext "github.com/netbirdio/netbird/management/server/context"
	"github.com/netbirdio/netbird/management/server/geolocation"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/shared/auth"
)

func TestDefaultAccountManager_DashboardLoginEventLocation(t *testing.T) {
	clientIP := netip.MustParseAddr("203.0.113.10")

	tests := []struct {
		name         string
		geo          geolocation.Geolocation
		withClientIP bool
		wantMeta     map[string]any
		wantAbsent   []string
	}{
		{
			name:         "ip without geolocation",
			withClientIP: true,
			wantMeta:     map[string]any{"location_connection_ip": "203.0.113.10"},
			wantAbsent:   []string{"location_country_code", "location_city_name", "location_geo_name_id"},
		},
		{
			name:         "ip with geolocation",
			geo:          &fakeGeo{geoNameID: 100, isoCode: "US", cityName: "City A"},
			withClientIP: true,
			wantMeta: map[string]any{
				"location_connection_ip": "203.0.113.10",
				"location_country_code":  "US",
				"location_city_name":     "City A",
				"location_geo_name_id":   uint(100),
			},
		},
		{
			name:         "failed lookup keeps the ip",
			geo:          &fakeGeo{err: assert.AnError},
			withClientIP: true,
			wantMeta:     map[string]any{"location_connection_ip": "203.0.113.10"},
			wantAbsent:   []string{"location_country_code", "location_city_name", "location_geo_name_id"},
		},
		{
			name:       "no client ip on the context",
			geo:        &fakeGeo{geoNameID: 100, isoCode: "US"},
			wantAbsent: []string{"location_connection_ip", "location_country_code", "location_geo_name_id"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testStore, cleanup, err := store.NewTestStoreFromSQL(context.Background(), "", t.TempDir())
			require.NoError(t, err)
			t.Cleanup(cleanup)
			require.NoError(t, testStore.SaveAccount(context.Background(), newAccountWithId(context.Background(), mockAccountID, mockUserID, "", "", "", false)))

			eventStore := &activity.InMemoryEventStore{}
			am := DefaultAccountManager{
				Store:              testStore,
				eventStore:         eventStore,
				permissionsManager: permissions.NewManager(testStore),
				geo:                tc.geo,
			}

			ctx := context.Background()
			if tc.withClientIP {
				ctx = nbcontext.SetClientIP(ctx, clientIP)
			}

			// The first login only records the timestamp; the second one is a new dashboard login.
			first := time.Now().UTC().Add(-time.Hour)
			_, err = am.GetUserFromUserAuth(ctx, auth.UserAuth{UserId: mockUserID, AccountId: mockAccountID, LastLogin: first})
			require.NoError(t, err)
			_, err = am.GetUserFromUserAuth(ctx, auth.UserAuth{UserId: mockUserID, AccountId: mockAccountID, LastLogin: first.Add(time.Minute)})
			require.NoError(t, err)

			var event *activity.Event
			require.Eventually(t, func() bool {
				events, getErr := eventStore.Get(context.Background(), mockAccountID, 0, 100, false)
				require.NoError(t, getErr)
				for _, e := range events {
					if e.Activity == activity.DashboardLogin {
						event = e
						return true
					}
				}
				return false
			}, 5*time.Second, 10*time.Millisecond, "a new login should store a dashboard.login event")

			for k, v := range tc.wantMeta {
				assert.Equal(t, v, event.Meta[k], "meta %s", k)
			}
			for _, k := range tc.wantAbsent {
				assert.NotContains(t, event.Meta, k)
			}
			assert.Contains(t, event.Meta, "timestamp")
		})
	}
}
