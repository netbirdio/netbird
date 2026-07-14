package net

import (
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
)

// relaySocketBufferEnv overrides, in bytes, the receive and send buffer size
// applied to the UDP sockets that carry relayed WireGuard data. A value of "0"
// disables the sizing entirely; an empty or invalid value uses the default.
const relaySocketBufferEnv = "NB_WGPROXY_SOCKET_BUFFER"

// defaultRelaySocketBufferSize is the receive/send buffer applied by default to
// relayed-data UDP sockets. The OS default (typically ~208 KiB) is too small for
// a single high-rate relayed flow: sender-side kernel drops on a full receive
// buffer surface to the tunnelled TCP as loss and collapse its throughput.
const defaultRelaySocketBufferSize = 7 << 20 // 7 MiB

// socketBufferConn is the portable subset used for the fallback sizing path.
type socketBufferConn interface {
	SetReadBuffer(bytes int) error
	SetWriteBuffer(bytes int) error
}

// relaySocketBufferSize resolves the configured buffer size from the environment.
func relaySocketBufferSize() int {
	v := os.Getenv(relaySocketBufferEnv)
	if v == "" {
		return defaultRelaySocketBufferSize
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		log.Warnf("invalid %s value %q, using default %d", relaySocketBufferEnv, v, defaultRelaySocketBufferSize)
		return defaultRelaySocketBufferSize
	}
	return n
}

// SizeRelaySocketBuffers grows the receive and send buffers of a UDP socket that
// carries relayed data. On Linux it first tries SO_RCVBUFFORCE/SO_SNDBUFFORCE,
// which bypass net.core.rmem_max/wmem_max when the process is privileged; it
// falls back to the portable SetReadBuffer/SetWriteBuffer (clamped by those
// sysctls, but still above the OS default) when the forced path is unavailable.
// Setting NB_WGPROXY_SOCKET_BUFFER to 0 disables the sizing.
func SizeRelaySocketBuffers(conn any) {
	size := relaySocketBufferSize()
	if size == 0 {
		return
	}

	if !forceSocketBuffers(conn, size) {
		bc, ok := conn.(socketBufferConn)
		if !ok {
			log.Debugf("relay socket buffer sizing skipped: %T supports neither forced nor portable sizing", conn)
			return
		}
		if err := bc.SetReadBuffer(size); err != nil {
			log.Debugf("failed to set relay socket read buffer to %d: %s", size, err)
		}
		if err := bc.SetWriteBuffer(size); err != nil {
			log.Debugf("failed to set relay socket write buffer to %d: %s", size, err)
		}
	}

	logRelaySocketBuffers(conn)
}
