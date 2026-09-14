//go:build windows

package daemonaddr

import (
	"context"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

// daemonRunsAsSelf reads the owner of the daemon's pipe. A daemon running as the
// service account owns its pipe as LocalSystem, and an elevated one as
// BUILTIN\Administrators, so only a daemon the user started themselves matches.
func daemonRunsAsSelf(addr string) bool {
	name, ok := strings.CutPrefix(addr, pipeScheme)
	if !ok {
		return false
	}

	for _, path := range PipePaths(name) {
		// Bounded: this runs on the UI's path for deciding which controls to
		// offer, so a pipe that does not answer promptly must not stall it. A
		// timeout leaves the caller unprivileged, which only disables controls.
		ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
		conn, err := dialPipe(ctx, path)
		cancel()
		if err != nil {
			continue
		}

		owned := ipcauth.PipeOwnedBySelf(conn)
		if cerr := conn.Close(); cerr != nil {
			log.Debugf("close daemon pipe %s after ownership check: %v", path, cerr)
		}
		return owned
	}

	return false
}
