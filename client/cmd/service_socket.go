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

func listenOnAddress(addr string) (*socketListener, error) {
	network, address, err := parseListenAddress(addr)
	if err != nil {
		return nil, err
	}

	if network == "npipe" {
		path := pipePath(address)
		listener, err := listenNamedPipe(path)
		if err != nil {
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
		return "", "", fmt.Errorf("address must be in [unix|tcp]://[path|host:port] format: %q", addr)
	}

	switch network {
	case "unix", "tcp", "npipe":
		return network, address, nil
	default:
		return "", "", fmt.Errorf("unsupported daemon address protocol: %v", network)
	}
}

// pipePath maps a daemon-addr npipe name (e.g. "netbird" from "npipe://netbird")
// to a Windows named-pipe path (\\.\pipe\netbird). A caller may also pass a full
// \\.\pipe\ path, which is returned unchanged.
func pipePath(name string) string {
	if strings.HasPrefix(name, `\\`) {
		return name
	}
	return `\\.\pipe\` + name
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

func (l *socketListener) chmodUnixSocket(description string) error {
	if l == nil || l.network != "unix" {
		return nil
	}

	if err := os.Chmod(l.address, 0666); err != nil {
		return fmt.Errorf("failed setting %s permissions for %s: %w", description, l.address, err)
	}
	return nil
}
