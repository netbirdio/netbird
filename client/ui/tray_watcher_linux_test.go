//go:build linux && !(linux && 386)

package main

import (
	"bufio"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// An item the watcher cannot host must not be listed: the host is what notices
// the item leaving the bus, so a listed item without one stays listed forever
// after its client exits.
func TestUnhostedItemIsNotListed(t *testing.T) {
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", startSessionBus(t))

	conn, err := privateSessionBus()
	require.NoError(t, err, "connect the watcher")
	claimStatusNotifierWatcher(conn)
	t.Cleanup(func() { _ = conn.Close() })

	client, err := privateSessionBus()
	require.NoError(t, err, "connect the client")
	t.Cleanup(func() { _ = client.Close() })

	// The client serves nothing at the path it registers, so the icon fetch
	// fails and no host starts.
	err = client.Object(watcherName, watcherPath).
		Call(watcherIface+".RegisterStatusNotifierItem", 0, "/StatusNotifierItem").Err
	require.NoError(t, err, "register the item")

	listed := func() []string {
		v, err := client.Object(watcherName, watcherPath).GetProperty(watcherIface + ".RegisteredStatusNotifierItems")
		require.NoError(t, err, "read RegisteredStatusNotifierItems")
		items, _ := v.Value().([]string)
		return items
	}
	// The host attempt is asynchronous, so watch for a listing for a while
	// rather than reading the property once.
	var got []string
	for deadline := time.Now().Add(time.Second); len(got) == 0 && time.Now().Before(deadline); {
		time.Sleep(50 * time.Millisecond)
		got = listed()
	}
	assert.Empty(t, got, "an item without a host must not be listed")
}

// startSessionBus runs a private dbus-daemon for the test and returns its
// address, skipping when the binary is not installed.
func startSessionBus(t *testing.T) string {
	t.Helper()

	path, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("dbus-daemon not installed")
	}

	cmd := exec.Command(path, "--session", "--nofork", "--print-address")
	out, err := cmd.StdoutPipe()
	require.NoError(t, err, "pipe dbus-daemon output")
	require.NoError(t, cmd.Start(), "start dbus-daemon")
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	addr, err := bufio.NewReader(out).ReadString('\n')
	require.NoError(t, err, "read the bus address")
	return strings.TrimSpace(addr)
}
