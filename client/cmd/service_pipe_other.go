//go:build !windows

package cmd

import (
	"context"
	"fmt"
	"net"
	"runtime"
)

// listenNamedPipe is unsupported off Windows; named pipes are a Windows-only transport.
func listenNamedPipe(string) (net.Listener, error) {
	return nil, fmt.Errorf("named pipe daemon socket is only supported on Windows, not %s", runtime.GOOS)
}

// dialNamedPipe is unsupported off Windows.
func dialNamedPipe(context.Context, string) (net.Conn, error) {
	return nil, fmt.Errorf("named pipe daemon socket is only supported on Windows, not %s", runtime.GOOS)
}
