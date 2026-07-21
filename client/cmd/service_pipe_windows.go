//go:build windows

package cmd

import (
	"context"
	"net"
	"time"

	"github.com/Microsoft/go-winio"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

// listenNamedPipe creates the daemon control named pipe with a tight SDDL
// (SYSTEM + Administrators + interactive users). ListenPipe fails if the pipe
// already exists (first-instance semantics), which prevents a squatting process
// from pre-creating it — we surface that error loudly rather than falling back.
func listenNamedPipe(path string) (net.Listener, error) {
	return winio.ListenPipe(path, &winio.PipeConfig{
		SecurityDescriptor: ipcauth.DefaultPipeSDDL(),
	})
}

// dialNamedPipe connects to the daemon control named pipe.
func dialNamedPipe(ctx context.Context, path string) (net.Conn, error) {
	if deadline, ok := ctx.Deadline(); ok {
		timeout := time.Until(deadline)
		return winio.DialPipe(path, &timeout)
	}
	return winio.DialPipeContext(ctx, path)
}
