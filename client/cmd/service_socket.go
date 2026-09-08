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
func listenOnAddress(addr string, allowed []string) (*socketListener, error) {
	network, address, err := parseListenAddress(addr)
	if err != nil {
		return nil, err
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
// out of --allow-group. It is a no-op for a nil listener, and for anything that
// is not a Unix socket: a named pipe carries its access rules in the security
// descriptor it was created with.
func (l *socketListener) restrict(description string, allowed []string) error {
	if l == nil || l.network != "unix" {
		return nil
	}

	if err := applySocketAccess(l.address, allowed); err != nil {
		return fmt.Errorf("restrict %s socket %s: %w", description, l.address, err)
	}
	return nil
}
