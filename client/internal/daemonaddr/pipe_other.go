//go:build !windows

package daemonaddr

import (
	"context"
	"fmt"
	"net"
)

// dialPipePaths is Windows-only: no other platform serves the daemon on a named
// pipe.
func dialPipePaths(context.Context, []string) (net.Conn, error) {
	return nil, fmt.Errorf("named pipes are only supported on Windows")
}
