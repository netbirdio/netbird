//go:build !ios && !android

package cmd

import (
	"fmt"
	"net"
	"os"
	"strings"

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
	case "unix", "tcp":
		return network, address, nil
	default:
		return "", "", fmt.Errorf("unsupported daemon address protocol: %v", network)
	}
}

func removeStaleUnixSocket(path string) {
	stat, err := os.Stat(path)
	if err == nil && !stat.IsDir() {
		if err := os.Remove(path); err != nil {
			log.Debugf("remove socket file: %v", err)
		}
		return
	}

	if err != nil && !os.IsNotExist(err) {
		log.Debugf("stat socket file: %v", err)
	}
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
