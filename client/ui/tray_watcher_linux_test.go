//go:build linux && !(linux && 386)

package main

import (
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
)

func TestDesktopWithOwnWatcher(t *testing.T) {
	tests := []struct {
		name    string
		desktop string
		want    string
	}{
		{"cinnamon", "X-Cinnamon", "X-Cinnamon"},
		{"mint uses a list", "X-Cinnamon:Cinnamon", "X-Cinnamon"},
		{"case insensitive", "kde", "kde"},
		{"xfce", "XFCE", "XFCE"},
		{"second entry matches", "Unknown:KDE", "KDE"},
		{"padded entry", "Unknown: XFCE ", " XFCE "},
		{"gnome has no watcher of its own", "GNOME", ""},
		{"minimal wm", "i3", ""},
		{"unset", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_CURRENT_DESKTOP", tc.desktop)
			assert.Equal(t, tc.want, desktopWithOwnWatcher(), "XDG_CURRENT_DESKTOP=%q", tc.desktop)
		})
	}
}

func TestItemObjectPath(t *testing.T) {
	tests := []struct {
		name    string
		service string
		want    dbus.ObjectPath
	}{
		{"qt sends the object path", "/StatusNotifierItem", "/StatusNotifierItem"},
		{"ayatana path", "/org/ayatana/NotificationItem/app", "/org/ayatana/NotificationItem/app"},
		{"libappindicator sends the bus name", ":1.84", defaultItemPath},
		{"well-known bus name", "org.kde.StatusNotifierItem-1234-1", defaultItemPath},
		{"malformed path", "//bad path", defaultItemPath},
		{"empty", "", defaultItemPath},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, itemObjectPath(tc.service), "service %q", tc.service)
		})
	}
}
