//go:build !js

package netstack

import (
	"fmt"
	"net"
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
)

const (
	EnvUseNetstackMode = "NB_USE_NETSTACK_MODE"

	// EnvSocks5ListenerPort overrides the port the SOCKS5 proxy listens on.
	EnvSocks5ListenerPort = "NB_SOCKS5_LISTENER_PORT"

	// EnvSocks5ListenerAddress overrides the host/IP the SOCKS5 proxy binds to.
	// The proxy is a bridge for local host applications into the userspace
	// WireGuard netstack, so it binds to loopback by default. Override this only
	// when the proxy must be reachable from other hosts (e.g. a container
	// gateway); doing so exposes an unauthenticated SOCKS5 proxy on that
	// address.
	EnvSocks5ListenerAddress = "NB_SOCKS5_LISTENER_ADDRESS"

	// defaultSocks5Host is the loopback address the SOCKS5 proxy binds to unless
	// overridden via EnvSocks5ListenerAddress.
	defaultSocks5Host = "127.0.0.1"
)

// IsEnabled todo: move these function to cmd layer
func IsEnabled() bool {
	return os.Getenv(EnvUseNetstackMode) == "true"
}

func ListenAddr() string {
	return fmt.Sprintf("%s:%d", listenHost(), listenPort())
}

// listenHost returns the host/IP the SOCKS5 proxy binds to. It defaults to
// loopback and only honors EnvSocks5ListenerAddress when it holds a valid IP.
func listenHost() string {
	addr := os.Getenv(EnvSocks5ListenerAddress)
	if addr == "" {
		return defaultSocks5Host
	}
	if net.ParseIP(addr) == nil {
		log.Warnf("invalid socks5 listener address %q, falling back to default: %s", addr, defaultSocks5Host)
		return defaultSocks5Host
	}
	return addr
}

// listenPort returns the port the SOCKS5 proxy binds to, defaulting to
// DefaultSocks5Port when EnvSocks5ListenerPort is unset or invalid.
func listenPort() int {
	sPort := os.Getenv(EnvSocks5ListenerPort)
	if sPort == "" {
		return DefaultSocks5Port
	}

	port, err := strconv.Atoi(sPort)
	if err != nil {
		log.Warnf("invalid socks5 listener port, unable to convert it to int, falling back to default: %d", DefaultSocks5Port)
		return DefaultSocks5Port
	}
	if port < 1 || port > 65535 {
		log.Warnf("invalid socks5 listener port, it should be in the range 1-65535, falling back to default: %d", DefaultSocks5Port)
		return DefaultSocks5Port
	}

	return port
}
