package consoleuser

import (
	"github.com/godbus/dbus/v5"
)

const (
	loginDest      = "org.freedesktop.login1"
	loginPath      = dbus.ObjectPath("/org/freedesktop/login1")
	loginInterface = "org.freedesktop.login1.Manager"
	listSessions   = loginInterface + ".ListSessions"

	sessionInterface = "org.freedesktop.login1.Session"
	sessionActive    = sessionInterface + ".Active"
	sessionClass     = sessionInterface + ".Class"
)

// activeUID queries systemd-logind for the active local user session and
// returns that user's UID. Falls back to (0, false) on any error or when no
// active user session exists (headless box, no GUI, no login at the console).
func activeUID() (uint32, bool) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return 0, false
	}

	mgr := conn.Object(loginDest, loginPath)

	// ListSessions returns []struct{ID string; UID uint32; User string;
	// Seat string; Path dbus.ObjectPath}.
	var sessions []struct {
		ID   string
		UID  uint32
		User string
		Seat string
		Path dbus.ObjectPath
	}
	if err := mgr.Call(listSessions, 0).Store(&sessions); err != nil {
		return 0, false
	}

	for _, s := range sessions {
		obj := conn.Object(loginDest, s.Path)

		active, err := obj.GetProperty(sessionActive)
		if err != nil || active.Value() != true {
			continue
		}

		class, err := obj.GetProperty(sessionClass)
		if err != nil {
			continue
		}
		// Only "user" sessions count; "greeter" / "lock-screen" / etc. are
		// not someone we should grant ownership to.
		if classStr, ok := class.Value().(string); !ok || classStr != "user" {
			continue
		}

		return s.UID, true
	}

	return 0, false
}
