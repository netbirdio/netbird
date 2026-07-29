//go:build windows

package cmd

import (
	"context"
	"net"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

// listenNamedPipe creates the daemon control named pipe with a permissive,
// local-only SDDL. Any local caller may connect, like Unix socket with 0666.
func listenNamedPipe(path string) (net.Listener, error) {
	return winio.ListenPipe(path, &winio.PipeConfig{
		SecurityDescriptor: ipcauth.DefaultPipeSDDL(),
	})
}

// dialNamedPipe connects to the daemon ipc named pipe at SECURITY_IDENTIFICATION.
func dialNamedPipe(ctx context.Context, path string) (net.Conn, error) {
	access := uint32(windows.GENERIC_READ | windows.GENERIC_WRITE)
	// winio's plain DialPipe connects at SECURITY_ANONYMOUS, under which the
	// daemon cannot read the caller's token. Identification lets the daemon
	// read its SID/groups without granting it the ability to act as the caller.
	return winio.DialPipeAccessImpLevel(ctx, path, access, winio.PipeImpLevelIdentification)
}
