//go:build !android && !ios && !freebsd && !js

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/wailsapp/wails/v3/pkg/services/notifications"

	"github.com/netbirdio/netbird/client/mdm"
	"github.com/netbirdio/netbird/client/ui/updater"
)

// An admin who turns notifications off, by hand or through MDM
// disableNotifications, must not see the new-version notification either.
func TestSendUpdateNotification_FollowsNotificationsSetting(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		want    int
	}{
		{name: "enabled", enabled: true, want: 1},
		{name: "disabled", enabled: false, want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sent []notifications.NotificationOptions
			u := &trayUpdater{
				send: func(o notifications.NotificationOptions) error {
					sent = append(sent, o)
					return nil
				},
				notificationsEnabled: func() bool { return tc.enabled },
			}

			u.sendUpdateNotification(updater.State{Available: true, Version: "9.9.9"})

			assert.Len(t, sent, tc.want, "update notifications sent with notifications enabled=%v", tc.enabled)
		})
	}
}

// The tray caches the user's setting and refreshes it only on daemon events,
// which do not fire for a policy change while disconnected: the MDM key must
// still win at the moment a notification is due.
func TestIsNotificationsEnabled_ReadsMDMPolicyLive(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy string
		cached bool
		want   bool
	}{
		{name: "policy turns them off over the cache", policy: `{"disableNotifications": true}`, cached: true, want: false},
		{name: "policy turns them on over the cache", policy: `{"disableNotifications": false}`, cached: false, want: true},
		{name: "no policy keeps the user setting", policy: ``, cached: false, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := &Tray{
				svc:                  TrayServices{MDMLoader: mdm.NewJSONLoader(func() string { return tc.policy })},
				notificationsEnabled: tc.cached,
			}

			assert.Equal(t, tc.want, tr.isNotificationsEnabled(), "notifications enabled")
		})
	}
}
