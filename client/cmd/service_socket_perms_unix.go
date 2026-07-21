//go:build !windows && !ios && !android

package cmd

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
	"github.com/netbirdio/netbird/client/internal/shell"
)

// secureDaemonListener applies the Layer-1 access control to the daemon control
// socket and returns the listener to serve on. For a Unix socket this restricts
// the socket to an owner (plus the netbird group); for anything else it is a
// no-op (TCP is legacy/unauthenticated; named pipes are gated by their SDDL).
func secureDaemonListener(l *socketListener) (net.Listener, error) {
	if l.network != "unix" {
		return l.Listener, nil
	}

	owner := effectiveSocketOwner()
	switch {
	case strictSocketDisabled:
		// Root-only opt-out (via service.json): leave it world-writable.
		if err := os.Chmod(l.address, 0666); err != nil {
			return nil, fmt.Errorf("set daemon socket permissions: %w", err)
		}
		log.Warnf("daemon control socket left world-writable (0666) by --disable-strict-socket")
		return l.Listener, nil

	case owner != "":
		// Seeded owner (flag, MDM, or persisted TOFU result): restrict before
		// serving so there is no open window.
		uid, err := lookupUser(owner)
		if err != nil {
			return nil, fmt.Errorf("lookup socket owner %q: %w", owner, err)
		}
		if err := restrictSocket(l.address, uid); err != nil {
			return nil, fmt.Errorf("restrict socket to %q: %w", owner, err)
		}
		return l.Listener, nil

	default:
		// Trust-on-first-use: open the socket now; tofuListener locks it to the
		// first caller's uid on the first connection.
		if err := os.Chmod(l.address, 0666); err != nil {
			return nil, fmt.Errorf("set daemon socket permissions: %w", err)
		}
		return &tofuListener{Listener: l.Listener, path: l.address, owner: -1}, nil
	}
}

func lookupUser(username string) (int, error) {
	u, err := shell.LookupWithGetent(username)
	if err != nil {
		return -1, fmt.Errorf("lookup user %s: %w", username, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return -1, fmt.Errorf("parse uid %s: %w", u.Uid, err)
	}
	return uid, nil
}

// addGroup creates a system group if it doesn't already exist and returns the gid.
// Must run as root.
func addGroup(name string) (int, error) {
	group, err := shell.LookupGroupWithGetent(name)
	if err == nil {
		gid, err := strconv.ParseInt(group.Gid, 10, 64)
		return int(gid), err
	}

	groupadd, err := exec.LookPath("groupadd")
	if err != nil {
		// Fallback for Alpine/BusyBox systems.
		if groupadd, err = exec.LookPath("addgroup"); err != nil {
			return -1, errors.New("neither groupadd nor addgroup found")
		}
	}

	// Use --system for a service/daemon group (no login, low GID).
	out, err := exec.Command(groupadd, "--system", name).CombinedOutput()
	if err != nil {
		return -1, fmt.Errorf("create group %q: %w: %s", name, err, out)
	}
	if group, err := shell.LookupGroupWithGetent(name); err == nil {
		gid, err := strconv.ParseInt(group.Gid, 10, 64)
		return int(gid), err
	}
	return -1, fmt.Errorf("lookup group %q: %w", name, err)
}

// restrictSocket locks the unix socket down to the owner uid plus the netbird
// group (0660). If the group cannot be created or applied, it fails closed to
// owner-only 0600 — it never leaves the socket world-writable.
func restrictSocket(path string, uid int) error {
	gid, err := addGroup("netbird")
	if err != nil {
		log.Errorf("create netbird group, failing closed to owner-only 0600: %v", err)
		return chownChmod(path, uid, -1, 0600)
	}
	if err := chownChmod(path, uid, gid, 0660); err != nil {
		log.Errorf("apply netbird group to socket, failing closed to owner-only 0600: %v", err)
		return chownChmod(path, uid, -1, 0600)
	}
	return nil
}

// chownChmod sets ownership and mode on the socket. A gid of -1 leaves the
// group unchanged.
func chownChmod(path string, uid, gid int, mode os.FileMode) error {
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("chown socket %s: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("chmod socket %s: %w", path, err)
	}
	return nil
}

// tofuListener implements trust-on-first-use for the daemon control socket.
// The socket starts world-writable; the first caller's uid (read via SO_PEERCRED)
// becomes the owner. On that first connection the socket is restricted and the
// owner persisted so the open window never reopens on later starts. Connections
// that raced in during the open window and are neither the owner nor root are
// dropped. Changing the socket mode does not disturb the already-open
// connection, so the first caller's request is served normally.
type tofuListener struct {
	net.Listener
	path  string
	mu    sync.Mutex
	owner int // -1 until claimed
}

func (l *tofuListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		id, err := ipcauth.PeerIdentity(c)
		if err != nil {
			log.Errorf("read peer credentials, dropping connection: %v", err)
			_ = c.Close()
			continue
		}
		uid := int(id.UID)

		l.mu.Lock()
		if l.owner == -1 {
			if err := restrictSocket(l.path, uid); err != nil {
				l.mu.Unlock()
				_ = c.Close()
				// Refuse to serve on a socket we could not lock down.
				return nil, fmt.Errorf("restrict socket on first connection: %w", err)
			}
			l.owner = uid
			persistSocketOwner(uid)
			log.Infof("control socket restricted to first caller (uid %d)", uid)
			l.mu.Unlock()
			return c, nil
		}
		owner := l.owner
		l.mu.Unlock()

		// New connects are already gated by the 0660 perms set above; this only
		// drops anything that slipped in during the brief open window.
		if uid != owner && uid != 0 {
			log.Warnf("dropping non-owner connection (uid %d) during socket bootstrap", uid)
			_ = c.Close()
			continue
		}
		return c, nil
	}
}

// effectiveSocketOwner returns the configured socket owner: the --socket-owner
// flag when set, otherwise the owner persisted by a previous TOFU migration.
func effectiveSocketOwner() string {
	if socketOwner != "" {
		return socketOwner
	}
	params, err := loadServiceParams()
	if err != nil {
		log.Errorf("load service params for socket owner: %v", err)
		return ""
	}
	if params != nil {
		return params.SocketOwner
	}
	return ""
}

// persistSocketOwner records the TOFU-selected owner (by username) so the next
// daemon start restricts the socket immediately, with no open window.
func persistSocketOwner(uid int) {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		log.Errorf("resolve uid %d to username for persistence: %v", uid, err)
		return
	}
	params, err := loadServiceParams()
	if err != nil {
		log.Errorf("load service params to persist socket owner: %v", err)
		return
	}
	if params == nil {
		params = currentServiceParams()
	}
	params.SocketOwner = u.Username
	if err := saveServiceParams(params); err != nil {
		log.Errorf("persist socket owner: %v", err)
	}
}
