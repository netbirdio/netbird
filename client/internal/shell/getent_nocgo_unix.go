//go:build (!cgo || osusergo) && !windows

package shell

import (
	"os"
	"os/user"
	"strconv"

	log "github.com/sirupsen/logrus"
)

// LookupWithGetent looks up a user by name, falling back to getent if os/user fails.
// Without CGO, os/user only reads /etc/passwd and misses NSS-provided users.
// getent goes through the host's NSS stack.
func LookupWithGetent(username string) (*user.User, error) {
	u, err := user.Lookup(username)
	if err == nil {
		return u, nil
	}

	stdErr := err
	log.Debugf("os/user.Lookup(%q) failed, trying getent: %v", username, err)

	u, _, getentErr := runGetentPasswd(username)
	if getentErr != nil {
		log.Debugf("getent fallback for %q also failed: %v", username, getentErr)
		return nil, stdErr
	}

	return u, nil
}

// LookupGroupWithGetent returns the resolved group from either a gid or groupname,
// falling back to getent if os/user fails (NSS groups under nocgo).
func LookupGroupWithGetent(name string) (*user.Group, error) {
	g, err := user.LookupGroup(name)
	if err == nil {
		return g, nil
	}

	stdErr := err
	log.Debugf("os/user.LookupGroup(%q) failed, trying getent: %v", name, err)
	g, getentErr := runGetentGroup(name)
	if getentErr != nil {
		log.Debugf("getent fallback for %q also failed: %v", name, getentErr)
		return nil, stdErr
	}
	return g, nil
}

// CurrentUserWithGetent gets the current user, falling back to getent if os/user fails.
func CurrentUserWithGetent() (*user.User, error) {
	u, err := user.Current()
	if err == nil {
		return u, nil
	}

	stdErr := err
	uid := strconv.Itoa(os.Getuid())
	log.Debugf("os/user.Current() failed, trying getent with UID %s: %v", uid, err)

	u, _, getentErr := runGetentPasswd(uid)
	if getentErr != nil {
		return nil, stdErr
	}

	return u, nil
}

// GroupIdsWithFallback gets group IDs for a user via the id command first,
// falling back to user.GroupIds().
// NOTE: unlike LookupWithGetent/CurrentUserWithGetent which try stdlib first,
// this intentionally tries `id -G` first because without CGO, user.GroupIds()
// only reads /etc/group and silently returns incomplete results for NSS users
// (no error, just missing groups). The id command goes through NSS and returns
// the full set.
func GroupIdsWithFallback(u *user.User) ([]string, error) {
	ids, err := runIdGroups(u.Username)
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
