//go:build !windows

package elevate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/getent"
)

// checkOnlyOwnerWritable reports an error unless path, and every directory leading
// to it, is owned by either root or this user and writable by nobody who could not
// already act as its owner. A writable directory is as good as a writable file,
// since anything in it can be replaced, so the whole chain is checked.
func checkOnlyOwnerWritable(path string) error {
	self := uint32(os.Getuid())

	for dir := path; ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil {
			return fmt.Errorf("stat %s: %w", dir, err)
		}

		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("file ownership is unavailable on this platform")
		}
		if stat.Uid != 0 && stat.Uid != self {
			return fmt.Errorf("%s is owned by uid %d, neither root nor this user", dir, stat.Uid)
		}

		if err := checkWriteBits(dir, info, stat.Uid, stat.Gid); err != nil {
			return err
		}

		if parent := filepath.Dir(dir); parent == dir {
			return nil
		}
	}
}

func checkWriteBits(path string, info os.FileInfo, uid, gid uint32) error {
	// On a directory the sticky bit stands in for the write bits: whoever may
	// write there still cannot replace an entry they do not own, which is the
	// only thing that would matter to us. /tmp is the usual example.
	sticky := info.IsDir() && info.Mode()&os.ModeSticky != 0

	return writeBitsAllow(path, info.Mode().Perm(), sticky, groupWriteAllowed(uid, gid))
}

// writeBitsAllow decides on the permission bits alone, given whether the group's
// write access has been vouched for.
func writeBitsAllow(path string, perm os.FileMode, sticky, groupAllowed bool) error {
	if sticky {
		return nil
	}
	if perm&0o020 != 0 && !groupAllowed {
		return fmt.Errorf("%s is writable by a group with members other than its owner (%v)", path, perm)
	}
	if perm&0o002 != 0 {
		return fmt.Errorf("%s is world-writable (%v)", path, perm)
	}
	return nil
}

// groupWriteAllowed reports whether a group's write access to a file owned by uid
// puts it in reach of anyone who could not already act as that owner.
//
// Two ways it does not. A group in adminWriteGIDs holds the accounts that can
// answer the elevation prompt anyway. And a user private group is how Debian,
// Ubuntu and Fedora ship: their umask of 002 makes a home directory and
// everything built in it group-writable, so refusing that would refuse every
// build not installed from a package.
func groupWriteAllowed(uid, gid uint32) bool {
	if slices.Contains(adminWriteGIDs, gid) {
		return true
	}

	group, err := getent.LookupGroupID(strconv.FormatUint(uint64(gid), 10))
	if err != nil {
		log.Debugf("cannot look up group %d, treating it as shared: %v", gid, err)
		return false
	}
	owner, err := getent.LookupUserID(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		log.Debugf("cannot look up uid %d, treating its group as shared: %v", uid, err)
		return false
	}

	if group.Name != owner.Username {
		return false
	}
	return !groupHasOtherMembers(group.Name, owner.Username)
}

// groupHasOtherMembers reports whether the group lists a member besides owner.
//
// Sharing the owner's name is what a user private group is recognised by, and it
// says nothing about who is in it: a group that has since gained a member is
// still named that way, and that member can write whatever the group can. So the
// membership is read rather than assumed. A group whose members cannot be
// listed, because no source on this host describes it, is treated as shared:
// the name alone cannot vouch for who writes through it.
func groupHasOtherMembers(name, owner string) bool {
	members, err := getent.GroupMembers(name)
	if err != nil {
		log.Debugf("cannot list the members of group %q, treating it as shared: %v", name, err)
		return true
	}
	return slices.ContainsFunc(members, func(member string) bool { return member != owner })
}
