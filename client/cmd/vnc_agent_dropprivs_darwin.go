//go:build darwin && !ios

package cmd

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// dropAgentPrivileges drops the vnc-agent process from root (its
// launchctl-asuser-inherited starting uid) to the target console user
// before any other initialisation runs. Without this the agent runs as
// root for the lifetime of the session; any post-auth memory-safety
// issue in the capture/input/encode paths would then be a root-level
// RCE on the host instead of a user-level one. Also makes the daemon's
// LOCAL_PEERCRED check correctly identify the agent as the console user,
// not as root.
//
// Returns an error when the agent is running as a non-root uid that
// differs from targetUID: non-root can only setuid to itself, so a
// mismatch here means the spawn went to the wrong session.
func dropAgentPrivileges(targetUID uint32) error {
	if targetUID == 0 {
		return fmt.Errorf("refusing to keep agent running as root (target uid 0)")
	}
	cur := uint32(os.Getuid())
	if cur == targetUID {
		return nil
	}
	if cur != 0 {
		return fmt.Errorf("agent uid %d does not match expected %d and we lack root to fix it", cur, targetUID)
	}
	// Resolve the target user's real primary group rather than reusing
	// targetUID as the gid: a user's primary group on macOS is typically
	// staff(20), not gid==uid. Fail closed if the lookup fails.
	targetGID, err := primaryGroupID(targetUID)
	if err != nil {
		return err
	}
	// Drop supplementary groups first: setgid alone doesn't touch the
	// auxiliary group list, leaving root's groups attached would let the
	// dropped process write to root-only group-writable files.
	if err := syscall.Setgroups([]int{}); err != nil {
		return fmt.Errorf("setgroups([]): %w", err)
	}
	if err := syscall.Setgid(targetGID); err != nil {
		return fmt.Errorf("setgid(%d): %w", targetGID, err)
	}
	if err := syscall.Setuid(int(targetUID)); err != nil {
		return fmt.Errorf("setuid(%d): %w", targetUID, err)
	}
	if uint32(os.Getuid()) != targetUID || uint32(os.Geteuid()) != targetUID {
		return fmt.Errorf("setuid verification: uid=%d euid=%d, expected %d", os.Getuid(), os.Geteuid(), targetUID)
	}
	return nil
}

// primaryGroupID resolves the real primary group id of the user with the
// given uid. Fails closed: a lookup or parse error returns an error so the
// caller never falls back to using uid as the gid.
func primaryGroupID(targetUID uint32) (int, error) {
	u, err := user.LookupId(strconv.Itoa(int(targetUID)))
	if err != nil {
		return 0, fmt.Errorf("look up uid %d: %w", targetUID, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return 0, fmt.Errorf("parse gid %q for uid %d: %w", u.Gid, targetUID, err)
	}
	return gid, nil
}
