//go:build windows

package cmd

import (
	"errors"
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/daemonaddr"
	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

// listenNamedPipe creates the daemon control pipe and reports the path it ended
// up on. The security descriptor lets any local caller connect, as a Unix socket
// at 0666 does, and the privileged operations are authorized separately from the
// caller's token.
//
// The protected name comes first so that an unprivileged process cannot take the
// name before the service does. Creating it requires being an administrator or
// LocalSystem, so a daemon an ordinary user runs themselves, as in netstack mode,
// falls back to the plain name; clients try both and check who serves them.
func listenNamedPipe(name string) (net.Listener, string, error) {
	var errs []error
	for _, path := range daemonaddr.PipePaths(name) {
		listener, err := winio.ListenPipe(path, &winio.PipeConfig{
			SecurityDescriptor: ipcauth.DefaultPipeSDDL(),
		})
		if err != nil {
			log.Debugf("not serving the daemon on %s: %v", path, err)
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
			continue
		}
		return listener, path, nil
	}

	return nil, "", errors.Join(errs...)
}
