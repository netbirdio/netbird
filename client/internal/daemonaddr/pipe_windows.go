//go:build windows

package daemonaddr

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"

	"github.com/Microsoft/go-winio"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

// dialPipePaths connects to the first path that answers with a pipe server this
// client may trust. When none does, it returns an access-denied error if any
// path gave one, and the last error otherwise.
func dialPipePaths(ctx context.Context, paths []string) (net.Conn, error) {
	var lastErr, deniedErr error
	for _, path := range paths {
		conn, err := dialPipe(ctx, path)
		if err != nil {
			log.Debugf("dial daemon pipe %s: %v", path, err)
			if deniedErr == nil && errors.Is(err, fs.ErrPermission) {
				deniedErr = err
			}
			lastErr = err
			continue
		}

		// A pipe in the protected namespace could only have been created by an
		// administrator or LocalSystem, so its name is the guarantee. Any other
		// name has to be checked, because any local user can create one.
		if !IsProtectedPipePath(path) {
			if err := ipcauth.PipeServerTrusted(conn); err != nil {
				if closeErr := conn.Close(); closeErr != nil {
					log.Debugf("close untrusted pipe %s: %v", path, closeErr)
				}
				lastErr = fmt.Errorf("%s: %w", path, err)
				continue
			}
		}

		return conn, nil
	}

	if deniedErr != nil {
		return nil, deniedErr
	}
	if lastErr == nil {
		lastErr = errors.New("no daemon pipe to connect to")
	}
	return nil, lastErr
}

// dialPipe connects to the daemon control pipe at SECURITY_IDENTIFICATION.
// winio's plain DialPipe connects at SECURITY_ANONYMOUS, under which the daemon
// cannot read the caller's token at all. Identification lets the daemon read the
// caller's SID and groups without granting it the ability to act as the caller.
func dialPipe(ctx context.Context, path string) (net.Conn, error) {
	access := uint32(windows.GENERIC_READ | windows.GENERIC_WRITE)
	return winio.DialPipeAccessImpLevel(ctx, path, access, winio.PipeImpLevelIdentification)
}
