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

func TestItemAddress(t *testing.T) {
	tests := []struct {
		name     string
		sender   dbus.Sender
		service  string
		wantBus  string
		wantPath dbus.ObjectPath
	}{
		{"libappindicator sends its object path", ":1.31", "/org/ayatana/NotificationItem/app", ":1.31", "/org/ayatana/NotificationItem/app"},
		{"wails sends the default path", ":1.14", "/StatusNotifierItem", ":1.14", "/StatusNotifierItem"},
		// Qt calls RegisterStatusNotifierItem from one connection and serves the
		// item on another, so the item lives on the bus it names, not on the
		// sender. Seen with CopyQ, which registered ":1.29" from ":1.23".
		{"qt names another connection", ":1.23", ":1.29", ":1.29", defaultItemPath},
		{"kstatusnotifieritem well-known name", ":1.22", "org.kde.StatusNotifierItem-1234-1", "org.kde.StatusNotifierItem-1234-1", defaultItemPath},
		{"malformed path stays on the sender", ":1.84", "//bad path", ":1.84", defaultItemPath},
		{"empty", ":1.84", "", ":1.84", defaultItemPath},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bus, path := itemAddress(tc.sender, tc.service)
			assert.Equal(t, tc.wantBus, bus, "bus for service %q", tc.service)
			assert.Equal(t, tc.wantPath, path, "path for service %q", tc.service)
		})
	}
}

func TestItemID(t *testing.T) {
	tests := []struct {
		name    string
		sender  dbus.Sender
		service string
		want    string
	}{
		{"bus name stands alone", ":1.84", ":1.84", ":1.84"},
		{"path is qualified by its sender", ":1.84", "/StatusNotifierItem", ":1.84/StatusNotifierItem"},
		{"other sender, same path", ":1.93", "/StatusNotifierItem", ":1.93/StatusNotifierItem"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, itemID(tc.sender, tc.service))
		})
	}
}

// Two clients both register the well-known path, as every Wails tray does, and
// neither may be mistaken for the other.
func TestItemIDDistinguishesSendersOnTheSamePath(t *testing.T) {
	const path = "/StatusNotifierItem"

	assert.NotEqual(t, itemID(":1.84", path), itemID(":1.93", path))
}
