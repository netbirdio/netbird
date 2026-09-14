//go:build !windows

package daemonaddr

import (
	"os"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
)

// daemonRunsAsSelf compares the owner of the daemon's Unix socket with this
// process's uid. Root is not treated specially here: a root caller is privileged
// on its own merits, and a root-owned socket says nothing about the caller.
func daemonRunsAsSelf(addr string) bool {
	path, ok := strings.CutPrefix(addr, "unix://")
	if !ok {
		return false
	}

	info, err := os.Stat(path)
	if err != nil {
		log.Debugf("stat daemon socket %s: %v", path, err)
		return false
	}

	// Only a socket says anything about a daemon. A directory or a leftover
	// regular file at that path is not one, and reading it as "the daemon runs as
	// us" would offer controls the daemon then refuses.
	if info.Mode()&os.ModeSocket == 0 {
		return false
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return stat.Uid == uint32(os.Getuid())
}
