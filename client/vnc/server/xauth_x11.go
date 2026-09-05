//go:build (linux && !android) || freebsd

package server

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/jezek/xgb"

	"github.com/netbirdio/netbird/client/configs"
)

// xauthFamilyLocal is the Xauth.h family value for AF_UNIX connections.
const (
	xauthFamilyLocal uint16 = 256
	xauthMITMagic           = "MIT-MAGIC-COOKIE-1"
)

// generateXAuthCookie returns a fresh 16-byte MIT-MAGIC-COOKIE-1 and its hex form.
func generateXAuthCookie() (cookie []byte, hexStr string, err error) {
	cookie = make([]byte, 16)
	if _, err := rand.Read(cookie); err != nil {
		return nil, "", fmt.Errorf("read random cookie: %w", err)
	}
	return cookie, hex.EncodeToString(cookie), nil
}

// writeXAuthFile writes a single MIT-MAGIC-COOKIE-1 entry in the binary
// Xauthority format, chowned to uid/gid and mode 0600.
func writeXAuthFile(path, hostname, display string, cookie []byte, uid, gid uint32) error {
	if len(cookie) != 16 {
		return fmt.Errorf("cookie must be 16 bytes")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0711); err != nil {
		return fmt.Errorf("mkdir xauth parent: %w", err)
	}
	// Ensure every component the daemon owns is traversable so the target
	// user's desktop process can reach its file. The leaf file is still
	// mode 0600 chowned to the user, and 0711 hides directory listings
	// from non-owners.
	if err := ensureTraversable(dir); err != nil {
		return fmt.Errorf("relax xauth parent perms: %w", err)
	}

	var buf []byte
	appendField := func(b []byte) {
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(b)))
		buf = append(buf, l[:]...)
		buf = append(buf, b...)
	}
	var fam [2]byte
	binary.BigEndian.PutUint16(fam[:], xauthFamilyLocal)
	buf = append(buf, fam[:]...)
	appendField([]byte(hostname))
	appendField([]byte(display))
	appendField([]byte(xauthMITMagic))
	appendField(cookie)

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0600); err != nil {
		return fmt.Errorf("write xauth tmp: %w", err)
	}
	if err := os.Chown(tmp, int(uid), int(gid)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("chown xauth tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename xauth: %w", err)
	}
	return nil
}

// ensureTraversable walks up from dir to configs.RuntimeDir (inclusive) and
// makes each component traversable by the session's user, so the X server can
// reach its Xauthority file. A dir outside the runtime dir is refused before
// anything is changed, so it never touches /var/run or /run.
//
// Only the execute bits are added, never a whole mode. The runtime dir is
// shared: the daemon advertises its socket there and unprivileged CLI and UI
// clients list it to find one, so setting it to 0711 would take away the read
// bit they need and break socket discovery. Execute alone grants traversal
// without exposing a listing.
func ensureTraversable(dir string) error {
	root := filepath.Clean(configs.RuntimeDir)
	if root == "" {
		return nil
	}
	cur := filepath.Clean(dir)
	if cur != root && !strings.HasPrefix(cur, root+string(os.PathSeparator)) {
		return fmt.Errorf("xauth dir %s is outside the runtime dir %s", cur, root)
	}
	for {
		if err := addTraversalBits(cur); err != nil {
			return err
		}
		if cur == root {
			return nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return nil
		}
		cur = parent
	}
}

// addTraversalBits ORs group and other execute onto dir's mode, leaving every
// other bit as it was. A directory that is already traversable is not touched.
func addTraversalBits(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat %s: %w", dir, err)
	}
	const traversal = 0o011
	mode := info.Mode().Perm()
	if mode&traversal == traversal {
		return nil
	}
	if err := os.Chmod(dir, mode|traversal); err != nil {
		return fmt.Errorf("chmod %s: %w", dir, err)
	}
	return nil
}

// dialXUnixWithCookie opens an xgb connection to display over AF_UNIX,
// authenticating with the supplied hex cookie instead of XAUTHORITY env.
func dialXUnixWithCookie(display, cookieHex string) (*xgb.Conn, error) {
	if len(display) < 2 || display[0] != ':' {
		return nil, fmt.Errorf("invalid X display %q", display)
	}
	sock := fmt.Sprintf("%s/X%s", x11SocketDir, display[1:])
	nc, err := net.Dial("unix", sock)
	if err != nil {
		return nil, fmt.Errorf("dial X socket %s: %w", sock, err)
	}
	conn, err := xgb.NewConnNetWithCookieHex(nc, cookieHex)
	if err != nil {
		_ = nc.Close()
		return nil, fmt.Errorf("xgb auth on %s: %w", display, err)
	}
	return conn, nil
}
