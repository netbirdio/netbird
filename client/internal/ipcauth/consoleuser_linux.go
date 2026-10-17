package ipcauth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	log "github.com/sirupsen/logrus"
)

const (
	loginDest      = "org.freedesktop.login1"
	loginPath      = dbus.ObjectPath("/org/freedesktop/login1")
	loginInterface = "org.freedesktop.login1.Manager"
	listSeats      = loginInterface + ".ListSeats"

	seatInterface     = "org.freedesktop.login1.Seat"
	seatActiveSession = seatInterface + ".ActiveSession"

	sessionInterface = "org.freedesktop.login1.Session"
	sessionActive    = sessionInterface + ".Active"
	sessionClass     = sessionInterface + ".Class"
	sessionRemote    = sessionInterface + ".Remote"
	sessionUser      = sessionInterface + ".User"

	// propertiesGet is the standard property reader. godbus offers no
	// context-aware GetProperty, and GetProperty is only this call underneath,
	// so a bounded read has to make it directly.
	propertiesGet = "org.freedesktop.DBus.Properties.Get"

	// nullObjectPath is what logind puts in an object path field that refers to
	// nothing, a seat with no session in the foreground being the one that
	// matters here.
	nullObjectPath = dbus.ObjectPath("/")

	// consoleLookupTimeout bounds the whole seat walk, not each call in it, so
	// a machine with several seats cannot multiply what an unanswering bus
	// costs. A healthy lookup is well under a millisecond.
	consoleLookupTimeout = 1 * time.Second
)

// isConsoleUser reports whether id holds the foreground session of one of this
// machine's seats.
//
// No seats means no console, which is the honest answer for a headless machine
// and the one that keeps its profiles to the privileged caller.
func isConsoleUser(id Identity) bool {
	// A SID belongs to a Windows principal and has no uid to compare. Nothing
	// on Linux produces one, and comparing anyway would match uid 0.
	if id.IsWindows() {
		return false
	}

	conn, err := dbus.SystemBus()
	if err != nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), consoleLookupTimeout)
	defer cancel()

	// ListSeats returns a(so): seat id and object path.
	var seats []struct {
		ID   string
		Path dbus.ObjectPath
	}
	if err := conn.Object(loginDest, loginPath).CallWithContext(ctx, listSeats, 0).Store(&seats); err != nil {
		log.Debugf("cannot list seats, treating the caller as not at the console: %v", err)
		return false
	}

	for _, seat := range seats {
		uid, ok := consoleSessionUID(ctx, conn, seat.Path)
		if ok && uid == id.UID {
			return true
		}
	}

	return false
}

// consoleSessionUID returns who holds a seat's foreground session, and false
// unless that session is a person logged in locally.
func consoleSessionUID(ctx context.Context, conn *dbus.Conn, seatPath dbus.ObjectPath) (uint32, bool) {
	// ActiveSession is (so): session id and object path. It names nothing on a
	// seat whose VT has been switched away from, and on one whose display
	// manager has not started a session yet.
	prop, err := property(ctx, conn.Object(loginDest, seatPath), seatActiveSession)
	if err != nil {
		return 0, false
	}
	var active struct {
		ID   string
		Path dbus.ObjectPath
	}
	if err := prop.Store(&active); err != nil {
		return 0, false
	}
	if active.ID == "" || active.Path == "" || active.Path == nullObjectPath {
		return 0, false
	}

	session := conn.Object(loginDest, active.Path)

	// Only "user" sessions count: a greeter or a lock screen is the display
	// manager sitting at the seat, not somebody to hand a profile to.
	if class, ok := stringProperty(ctx, session, sessionClass); !ok || class != "user" {
		return 0, false
	}

	// A remote session can hold a seat, and unlike the session's class and
	// type, which pam_systemd takes from the environment of whoever opened the
	// session, remoteness is set by the thing that accepted the connection. So
	// it is worth asking even once the seat is established.
	if remote, ok := boolProperty(ctx, session, sessionRemote); !ok || remote {
		return 0, false
	}

	// Implied by the seat having named this session, and kept as a cross-check
	// against a foreground that moved between the two calls.
	if isActive, ok := boolProperty(ctx, session, sessionActive); !ok || !isActive {
		return 0, false
	}

	// User is (uo): uid and the user object's path. Read from the session
	// object rather than carried over from a listing, so the uid returned and
	// the checks above are known to describe the same session.
	prop, err = property(ctx, session, sessionUser)
	if err != nil {
		return 0, false
	}
	var owner struct {
		UID  uint32
		Path dbus.ObjectPath
	}
	if err := prop.Store(&owner); err != nil {
		return 0, false
	}

	return owner.UID, true
}

// property reads one property under ctx, name being the interface.member form
// godbus takes. It is what GetProperty does, with a deadline the caller owns.
func property(ctx context.Context, obj dbus.BusObject, name string) (dbus.Variant, error) {
	idx := strings.LastIndex(name, ".")
	if idx < 0 || idx+1 == len(name) {
		return dbus.Variant{}, fmt.Errorf("invalid property name %q", name)
	}
	var v dbus.Variant
	err := obj.CallWithContext(ctx, propertiesGet, 0, name[:idx], name[idx+1:]).Store(&v)
	return v, err
}

func stringProperty(ctx context.Context, obj dbus.BusObject, name string) (string, bool) {
	prop, err := property(ctx, obj, name)
	if err != nil {
		return "", false
	}
	s, ok := prop.Value().(string)
	return s, ok
}

func boolProperty(ctx context.Context, obj dbus.BusObject, name string) (bool, bool) {
	prop, err := property(ctx, obj, name)
	if err != nil {
		return false, false
	}
	b, ok := prop.Value().(bool)
	return b, ok
}
