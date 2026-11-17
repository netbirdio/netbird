package daemonaddr

import (
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"
)

const (
	// EnvMaxRecvMsgSize overrides the default gRPC max receive message size for
	// connections to the daemon. Value is in bytes.
	EnvMaxRecvMsgSize = "NB_DAEMON_GRPC_MAX_MSG_SIZE"

	// defaultMaxRecvMsgSize is the max gRPC receive message size used for daemon
	// connections when EnvMaxRecvMsgSize is unset or invalid. It overrides the
	// gRPC library default of 4 MB, which a detailed status already exceeds on a
	// network of a few thousand peers.
	defaultMaxRecvMsgSize = 1024 * 1024 * 16
)

// MaxRecvMsgSize returns the max gRPC receive message size for daemon connections
// from the environment, or defaultMaxRecvMsgSize (16 MB) if unset or invalid.
func MaxRecvMsgSize() int {
	val := os.Getenv(EnvMaxRecvMsgSize)
	if val == "" {
		return defaultMaxRecvMsgSize
	}

	size, err := strconv.Atoi(val)
	if err != nil {
		log.Warnf("invalid %s value %q, using default: %v", EnvMaxRecvMsgSize, val, err)
		return defaultMaxRecvMsgSize
	}

	if size <= 0 {
		log.Warnf("invalid %s value %d, must be positive, using default", EnvMaxRecvMsgSize, size)
		return defaultMaxRecvMsgSize
	}

	return size
}
