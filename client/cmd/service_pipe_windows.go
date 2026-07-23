//go:build windows

package cmd

import (
	"context"
	"net"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"

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

// dialNamedPipe connects to the daemon control named pipe at SECURITY_IDENTIFICATION.
//
// winio's plain DialPipe connects at SECURITY_ANONYMOUS, under which the daemon
// cannot read the caller's token (ImpersonateNamedPipeClient fails / yields an
// anonymous token and the handshake is dropped). Identification lets the daemon
// *identify* the caller (read its SID/groups) without granting it the ability to
// act as the caller — the least privilege the daemon needs for authorization.
func dialNamedPipe(ctx context.Context, path string) (net.Conn, error) {
	access := uint32(windows.GENERIC_READ | windows.GENERIC_WRITE)
	return winio.DialPipeAccessImpLevel(ctx, path, access, winio.PipeImpLevelIdentification)
}
