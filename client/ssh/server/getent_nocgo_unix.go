//go:build (!cgo || osusergo) && !windows

package server

import (
	"os"
	"os/user"
	"strconv"

	log "github.com/sirupsen/logrus"
)

// lookupWithGetent looks up a user by name, falling back to getent if os/user fails.
// Without CGO, os/user only reads /etc/passwd and misses NSS-provided users.
// getent goes through the host's NSS stack.
func lookupWithGetent(username string) (*user.User, error) {
	u, err := user.Lookup(username)
	if err == nil {
		return u, nil
	}

	stdErr := err
	log.Debugf("os/user.Lookup(%q) failed, trying getent: %v", username, err)

	u, _, getentErr := runGetent(username)
	if getentErr != nil {
		log.Debugf("getent fallback for %q also failed: %v", username, getentErr)
		return nil, stdErr
	}

	return u, nil
}

// currentUserWithGetent gets the current user, falling back to getent if os/user fails.
func currentUserWithGetent() (*user.User, error) {
	u, err := user.Current()
	if err == nil {
		return u, nil
	}

	stdErr := err
	uid := strconv.Itoa(os.Getuid())
	log.Debugf("os/user.Current() failed, trying getent with UID %s: %v", uid, err)

	u, _, getentErr := runGetent(uid)
	if getentErr != nil {
		return nil, stdErr
	}

	return u, nil
}

// groupIdsWithFallback gets group IDs for a user via the id command first,
// falling back to user.GroupIds().
// NOTE: unlike lookupWithGetent/currentUserWithGetent which try stdlib first,
// this intentionally tries `id -G` first because without CGO, user.GroupIds()
// only reads /etc/group and silently returns incomplete results for NSS users
// (no error, just missing groups). The id command goes through NSS and returns
// the full set.
func groupIdsWithFallback(u *user.User) ([]string, error) {
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
