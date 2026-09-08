//go:build !windows && !ios && !android

package cmd

import (
	"fmt"
	"os"
	"strconv"

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

	if err := os.Chown(path, -1, gid); err != nil {
		return fmt.Errorf("set group to gid %d: %w", gid, err)
	}
	if err := os.Chmod(path, restrictedSocketMode); err != nil {
		return fmt.Errorf("set mode %#o: %w", restrictedSocketMode, err)
	}
	return nil
}

func gidPrincipal(gid string) (string, error) {
	if _, err := parseGID(gid); err != nil {
		return "", err
	}
	return allowGroupKindGID + ":" + gid, nil
}

func parseGID(value string) (int, error) {
	gid, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse gid %q: %w", value, err)
	}
	return int(gid), nil
}
