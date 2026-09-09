//go:build !windows && !ios && !android

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/netbirdio/netbird/client/internal/getent"
)

// Socket modes. openSocketMode is the historical one: any local account may
// connect, and what it may then do is decided from its kernel-attested
// identity. restrictedSocketMode is what --allow-group installs, where the
// kernel refuses the connect() outright for an account outside the group.
const (
	openSocketMode       os.FileMode = 0666
	restrictedSocketMode os.FileMode = 0660
)

// resolveAllowGroup resolves one --allow-group value to a "gid:<id>"
// principal. A numeric value, with or without the prefix, is the GID itself;
// anything else is a group name resolved through NSS, so groups that only
// LDAP, SSSD or winbind know about work as well as ones in /etc/group.
func resolveAllowGroup(value string) (string, error) {
	if kind, rest, ok := cutKind(value); ok {
		if kind != allowGroupKindGID {
			return "", fmt.Errorf("unsupported principal kind %q, use a group name or %s:<id>", kind, allowGroupKindGID)
		}
		return gidPrincipal(rest)
	}

	if _, err := parseGID(value); err == nil {
		return gidPrincipal(value)
	}

	group, err := getent.LookupGroupName(value)
	if err != nil {
		return "", fmt.Errorf("look up group: %w", err)
	}
	return gidPrincipal(group.Gid)
}

// checkAllowGroupSet rejects more than one principal: a Unix socket carries a
// single owning group, so a second one could not be enforced and must not be
// accepted as though it were.
func checkAllowGroupSet(principals []string) error {
	if len(principals) > 1 {
		return fmt.Errorf("--allow-group takes a single group on this platform, got %d: %v", len(principals), principals)
	}
	return nil
}

// applySocketAccess sets the access the socket grants to other accounts: the
// allowed group at 0660, or every local account at 0666 when no group is
// configured.
//
// The owner is left untouched so a daemon running as an ordinary user, as in a
// rootless container, keeps access to the socket it created. The group is set
// before the mode is widened, so the window between the two is one where the
// group has no access rather than one where it has access it should not.
func applySocketAccess(path string, principals []string) error {
	// The listener just bound this path, so anything else standing there now is
	// something another account substituted. Checked before either call below,
	// neither of which should ever act on a name the daemon did not create.
	if err := requireSocketFile(path); err != nil {
		return err
	}

	if len(principals) == 0 {
		if err := os.Chmod(path, openSocketMode); err != nil {
			return fmt.Errorf("set mode %#o: %w", openSocketMode, err)
		}
		return nil
	}

	value, ok := principalValue(principals[0], allowGroupKindGID)
	if !ok {
		return fmt.Errorf("not a %s principal: %q", allowGroupKindGID, principals[0])
	}
	gid, err := parseGID(value)
	if err != nil {
		return err
	}

	if err := requireTrustedSocketDir(filepath.Dir(path)); err != nil {
		return err
	}

	// Lchown, not Chown: chown follows symlinks, so a daemon running as root
	// would otherwise hand an arbitrary target away to the configured group if
	// the name were swapped between the check above and here.
	if err := os.Lchown(path, -1, gid); err != nil {
		return fmt.Errorf("set group to gid %d: %w", gid, err)
	}
	if err := os.Chmod(path, restrictedSocketMode); err != nil {
		return fmt.Errorf("set mode %#o: %w", restrictedSocketMode, err)
	}
	return nil
}

// requireSocketFile reports whether path is the socket the listener created,
// without following a symlink standing in its place.
func requireSocketFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s is not a socket (mode %s), refusing to change its access", path, info.Mode())
	}
	return nil
}

// requireTrustedSocketDir refuses to apply a restriction inside a directory
// where another account could swap the socket for something else between the
// check and the change. That is only true of a directory some other account can
// write to: a sticky directory is fine, since only the owner of an entry may
// replace it there.
//
// The default locations are root-owned, so this rejects nothing an ordinary
// install does. It exists because the socket paths are configurable.
func requireTrustedSocketDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat socket directory: %w", err)
	}

	mode := info.Mode()
	if mode.Perm()&0o022 != 0 && mode&os.ModeSticky == 0 {
		return fmt.Errorf("socket directory %s is writable by other accounts (mode %s), refusing to restrict a socket that they can replace", dir, mode.Perm())
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot read ownership of socket directory %s", dir)
	}
	if stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("socket directory %s is owned by uid %d, which is neither root nor this daemon", dir, stat.Uid)
	}
	return nil
}

// gidPrincipal renders a GID as a principal in its canonical decimal form, so
// that spellings of the same group ("gid:01" and "gid:1") produce one principal
// rather than two that later look like a request to use two groups.
func gidPrincipal(gid string) (string, error) {
	parsed, err := parseGID(gid)
	if err != nil {
		return "", err
	}
	return allowGroupKindGID + ":" + strconv.Itoa(parsed), nil
}

// unchangedGID is the value chown reads as "leave the group alone". A
// configured GID that lands on it would silently keep whatever group the socket
// already had, so it is rejected rather than applied.
const unchangedGID = 1<<32 - 1

func parseGID(value string) (int, error) {
	gid, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse gid %q: %w", value, err)
	}
	if gid == unchangedGID {
		return 0, fmt.Errorf("gid %d is not a usable group", gid)
	}
	return int(gid), nil
}
