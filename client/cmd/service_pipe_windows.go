//go:build windows

package cmd

import (
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/Microsoft/go-winio"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/daemonaddr"
	"github.com/netbirdio/netbird/client/internal/instance"
	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

const pipeProbeTimeout = 300 * time.Millisecond

// listenNamedPipe creates the daemon control pipe and reports the path it ended
// up on. The security descriptor lets any local caller connect, as a Unix socket
// at 0666 does, and the privileged operations are authorized separately from the
// caller's token.
//
// The protected name comes first so that an unprivileged process cannot take the
// name before the service does. Creating it requires being an administrator or
// LocalSystem, so a daemon an ordinary user runs themselves, as in netstack mode,
// falls back to the plain name; clients try both and check who serves them.
//
// A named installation does not fall back while its protected name is served:
// that is a second daemon of the same installation, and clients would reach
// either one depending on which started first.
func listenNamedPipe(name string) (net.Listener, string, error) {
	named := !instance.Current().IsDefault()
	var errs []error
	for _, path := range daemonaddr.PipePaths(name) {
		if named && daemonaddr.IsProtectedPipePath(path) && pipeInUse(path) {
			return nil, "", fmt.Errorf("pipe %s is already served by another daemon of this installation", path)
		}
		listener, err := winio.ListenPipe(path, &winio.PipeConfig{
			SecurityDescriptor: ipcauth.DefaultPipeSDDL(),
		})
		if err != nil {
			log.Debugf("not serving the daemon on %s: %v", path, err)
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
			if named && daemonaddr.IsProtectedPipePath(path) && pipeInUse(path) {
				return nil, "", fmt.Errorf("pipe %s is already served by another daemon of this installation", path)
			}
			continue
		}
		return listener, path, nil
	}

	return nil, "", errors.Join(errs...)
}

// pipeInUse reports whether a pipe exists. Only "not found" counts as free: a
// busy pipe, or one that refuses us, exists.
func pipeInUse(path string) bool {
	timeout := pipeProbeTimeout
	conn, err := winio.DialPipe(path, &timeout)
	if err == nil {
		if cerr := conn.Close(); cerr != nil {
			log.Debugf("close pipe probe %s: %v", path, cerr)
		}
		return true
	}
	return !errors.Is(err, os.ErrNotExist)
}
