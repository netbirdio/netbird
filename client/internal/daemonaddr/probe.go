package daemonaddr

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

// accessProbeTimeout bounds the probe.
const accessProbeTimeout = time.Second

// DeniesCaller reports whether the OS refuses this process access to the daemon
// socket or pipe at addr. It dials once without gRPC.
func DeniesCaller(ctx context.Context, addr string) bool {
	ctx, cancel := context.WithTimeout(ctx, accessProbeTimeout)
	defer cancel()

	conn, err := dialRaw(ctx, addr)
	if err != nil {
		return errors.Is(err, fs.ErrPermission)
	}
	if err := conn.Close(); err != nil {
		log.Debugf("close daemon access probe: %v", err)
	}
	return false
}

func dialRaw(ctx context.Context, addr string) (net.Conn, error) {
	if name, ok := strings.CutPrefix(addr, pipeScheme); ok {
		return dialPipePaths(ctx, PipePaths(name))
	}
	if path, ok := unixSocketPath(addr); ok {
		var d net.Dialer
		return d.DialContext(ctx, "unix", path)
	}
	// Loopback TCP is never group-restricted.
	return nil, errors.New("no socket access to probe for " + addr)
}

// unixSocketPath accepts unix:///abs and unix:path.
func unixSocketPath(addr string) (string, bool) {
	if path, ok := strings.CutPrefix(addr, "unix://"); ok {
		return path, true
	}
	return strings.CutPrefix(addr, "unix:")
}
