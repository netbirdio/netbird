//go:build !windows

package cmd

import (
	"fmt"
	"net"
)

// listenNamedPipe is Windows-only: no other platform serves the daemon on a
// named pipe.
func listenNamedPipe(string) (net.Listener, string, error) {
	return nil, "", fmt.Errorf("named pipes are only supported on Windows")
}
