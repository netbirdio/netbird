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
// sets mode 0711 on each component. Stops once it leaves the runtime dir so
// it never touches /var/run or /run.
func ensureTraversable(dir string) error {
	root := filepath.Clean(configs.RuntimeDir)
	if root == "" {
		return nil
	}
	cur := filepath.Clean(dir)
	for {
		if err := os.Chmod(cur, 0711); err != nil {
			return fmt.Errorf("chmod %s: %w", cur, err)
		}
		if cur == root {
			return nil
		}
		parent := filepath.Dir(cur)
		if parent == cur || !strings.HasPrefix(cur, root+string(os.PathSeparator)) {
			return nil
		}
		cur = parent
	}
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
