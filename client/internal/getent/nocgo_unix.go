//go:build (!cgo || osusergo) && !windows

package getent

import (
	"os"
	"os/user"
	"strconv"

	log "github.com/sirupsen/logrus"
)

// Without cgo, os/user only reads /etc/passwd and /etc/group and misses
// NSS-provided users and groups; the getent and id commands go through the
// host's NSS stack.

// LookupUser looks up a user by name, falling back to getent if os/user fails.
func LookupUser(username string) (*user.User, error) {
	u, err := user.Lookup(username)
	if err == nil {
		return u, nil
	}

	stdErr := err
	log.Debugf("os/user.Lookup(%q) failed, trying getent: %v", username, err)

	u, _, getentErr := passwdLookup(username)
	if getentErr != nil {
		log.Debugf("getent fallback for %q also failed: %v", username, getentErr)
		return nil, stdErr
	}
	return u, nil
}

// LookupUserID looks up a user by UID, falling back to getent if os/user fails.
func LookupUserID(uid string) (*user.User, error) {
	u, err := user.LookupId(uid)
	if err == nil {
		return u, nil
	}

	stdErr := err
	log.Debugf("os/user.LookupId(%q) failed, trying getent: %v", uid, err)

	u, _, getentErr := passwdLookup(uid)
	if getentErr != nil {
		log.Debugf("getent fallback for uid %s also failed: %v", uid, getentErr)
		return nil, stdErr
	}
	return u, nil
}

// CurrentUser returns the user this process runs as, falling back to getent
// if os/user fails.
func CurrentUser() (*user.User, error) {
	u, err := user.Current()
	if err == nil {
		return u, nil
	}

	stdErr := err
	uid := strconv.Itoa(os.Getuid())
	log.Debugf("os/user.Current() failed, trying getent with UID %s: %v", uid, err)

	u, _, getentErr := passwdLookup(uid)
	if getentErr != nil {
		return nil, stdErr
	}
	return u, nil
}

// LookupGroupID looks up a group by GID, falling back to getent if os/user
// fails.
func LookupGroupID(gid string) (*user.Group, error) {
	g, err := user.LookupGroupId(gid)
	if err == nil {
		return g, nil
	}

	stdErr := err
	log.Debugf("os/user.LookupGroupId(%q) failed, trying getent: %v", gid, err)

	g, _, getentErr := groupLookup(gid)
	if getentErr != nil {
		log.Debugf("getent fallback for gid %s also failed: %v", gid, getentErr)
		return nil, stdErr
	}
	return g, nil
}

// GroupIDs returns the IDs of the groups the user is a member of.
// NOTE: unlike the lookups above, which try the standard library first, this
// intentionally tries `id -G` first because without cgo, user.GroupIds only
// reads /etc/group and silently returns incomplete results for NSS users
// (no error, just missing groups). The id command goes through NSS and
// returns the full set.
func GroupIDs(u *user.User) ([]string, error) {
	ids, err := idGroups(u.Username)
	if err == nil {
		return ids, nil
	}

	log.Debugf("id -G %q failed, falling back to user.GroupIds(): %v", u.Username, err)

	ids, stdErr := u.GroupIds()
	if stdErr != nil {
		return nil, stdErr
	}
	return ids, nil
}
