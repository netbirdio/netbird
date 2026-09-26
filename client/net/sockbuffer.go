package net

import (
	"math"
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
)

// relaySocketBufferEnv sets, in bytes, the size that the receive and send buffers of
// the UDP sockets carrying relayed WireGuard data are grown to. Buffers already at least
// that large are left alone. "0" disables the sizing; empty or invalid uses the default.
const relaySocketBufferEnv = "NB_WGPROXY_SOCKET_BUFFER"

// defaultRelaySocketBufferSize is the receive/send buffer applied by default to
// relayed-data UDP sockets. The OS default (typically ~208 KiB) is too small for
// a single high-rate relayed flow: sender-side kernel drops on a full receive
// buffer surface to the tunnelled TCP as loss and collapse its throughput.
const defaultRelaySocketBufferSize = 7 << 20 // 7 MiB

// maxRelaySocketBufferSize is the largest size the kernel accepts before doubling it, and
// keeps the value within the int32 that setsockopt takes.
const maxRelaySocketBufferSize = math.MaxInt32 / 2

// relaySocketBufferSize resolves the configured buffer size from the environment.
func relaySocketBufferSize() int {
	v := os.Getenv(relaySocketBufferEnv)
	if v == "" {
		return defaultRelaySocketBufferSize
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		log.Warnf("invalid %s value %q, using default %d", relaySocketBufferEnv, v, defaultRelaySocketBufferSize)
		return defaultRelaySocketBufferSize
	}
	if n > maxRelaySocketBufferSize {
		log.Warnf("%s value %d exceeds the kernel limit, using %d", relaySocketBufferEnv, n, maxRelaySocketBufferSize)
		return maxRelaySocketBufferSize
	}
	return int(n)
}

// SizeRelaySocketBuffers grows the receive and send buffers of a UDP socket that carries
// relayed WireGuard data to the size set by NB_WGPROXY_SOCKET_BUFFER (7 MiB by default),
// and never shrinks a buffer that is already larger. Setting the variable to 0 disables
// the sizing. Only the Linux kernel-mode WireGuard proxies own such a socket, so this
// does nothing on other platforms.
func SizeRelaySocketBuffers(conn any) {
	size := relaySocketBufferSize()
	if size == 0 {
		return
	}

	growSocketBuffers(conn, size)
}
