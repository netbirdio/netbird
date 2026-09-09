//go:build !ios && !android

package cmd

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

type socketListener struct {
	net.Listener
	network string
	address string
}

// listenOnAddress opens the daemon listener for addr. allowed holds the
// resolved principals from --allow-group, empty when the socket is left open to
// every local account; on Windows they go into the pipe's security descriptor,
// on Unix they are applied to the socket file by applySocketAccess once the
// listener exists.
//
// A TCP address cannot express either, so a restriction configured against one
// is refused here, before anything is bound. Serving it anyway would leave the
// daemon reachable by anything that can open a socket to the port, on a host
// configured to be locked down.
func listenOnAddress(addr string, allowed []string) (*socketListener, error) {
	network, address, err := parseListenAddress(addr)
	if err != nil {
		return nil, err
	}

	if network == "tcp" && len(allowed) > 0 {
		return nil, fmt.Errorf("cannot restrict %s to %v: a tcp listener carries no local access control, use a unix socket or npipe://", addr, allowed)
	}

	if network == "npipe" {
		listener, path, err := listenNamedPipe(address, allowed) //nolint:staticcheck
		if err != nil {                                          //nolint:staticcheck // always errors on non-Windows builds
			return nil, err
		}
		return &socketListener{Listener: listener, network: network, address: path}, nil
	}

	if network == "unix" {
		removeStaleUnixSocket(address)

		// A Unix socket accepts connections the moment it is bound, and the
		// kernel checks its mode at connect() rather than at accept(). Creating
		// it owner-only closes the window between the bind and applySocketAccess:
		// without this, a permissive umask leaves the socket open to everybody
		// for that interval, and a caller that got in stays connected after the
		// mode is narrowed.
		listener, err := listenUnixPrivate(address)
		if err != nil {
			return nil, err
		}
		return &socketListener{Listener: listener, network: network, address: address}, nil
	}

	listener, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}

	return &socketListener{Listener: listener, network: network, address: address}, nil
}

func parseListenAddress(addr string) (string, string, error) {
	network, address, ok := strings.Cut(addr, "://")
	if !ok || network == "" || address == "" {
		return "", "", fmt.Errorf("address must be in [unix|tcp|npipe]://[path|host:port|name] format: %q", addr)
	}

	switch network {
	case "unix", "tcp", "npipe":
		return network, address, nil
	default:
		return "", "", fmt.Errorf("unsupported daemon address protocol: %v", network)
	}
}

func removeStaleUnixSocket(path string) {
	stat, err := os.Lstat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Debugf("stat socket file: %v", err)
		}
		return
	}

	if stat.Mode()&os.ModeSocket == 0 {
		return
	}

	if !isStaleUnixSocket(path) {
		return
	}

	if err := os.Remove(path); err != nil {
		log.Debugf("remove socket file: %v", err)
	}
}

func isStaleUnixSocket(path string) bool {
	conn, err := net.DialTimeout("unix", path, 100*time.Millisecond)
	if err == nil {
		if closeErr := conn.Close(); closeErr != nil {
			log.Debugf("close unix socket probe: %v", closeErr)
		}
		return false
	}

	if os.IsNotExist(err) || os.IsPermission(err) || os.IsTimeout(err) {
		log.Debugf("not removing unix socket %s after probe error: %v", path, err)
		return false
	}

	return errors.Is(err, syscall.ECONNREFUSED)
}

func removeStaleUnixSocketForAddress(addr string) {
	network, address, err := parseListenAddress(addr)
	if err != nil || network != "unix" {
		return
	}
	removeStaleUnixSocket(address)
}

// restrict sets the access the socket file grants, from the principals resolved
// out of --allow-group. It is a no-op for a nil listener, which is what a
// disabled JSON socket is, and for a named pipe, which carries its access rules
// in the security descriptor it was created with.
//
// Any other transport that cannot express the restriction is an error rather
// than a socket served without one. listenOnAddress refuses the same
// combination before binding; this is the backstop that keeps a transport added
// later from silently inheriting the unrestricted path.
func (l *socketListener) restrict(description string, allowed []string) error {
	if l == nil || l.network == "npipe" {
		return nil
	}

	if l.network != "unix" {
		if len(allowed) > 0 {
			return fmt.Errorf("cannot restrict the %s %s listener to %v", description, l.network, allowed)
		}
		return nil
	}

	if err := applySocketAccess(l.address, allowed); err != nil {
		return fmt.Errorf("restrict %s socket %s: %w", description, l.address, err)
	}
	return nil
}
