//go:build windows

package ipcauth

import (
	"context"
	"fmt"
	"net"
	"runtime"

	"golang.org/x/sys/windows"
	"google.golang.org/grpc/credentials"
)

var (
	modadvapi32                    = windows.NewLazySystemDLL("advapi32.dll")
	procImpersonateNamedPipeClient = modadvapi32.NewProc("ImpersonateNamedPipeClient")
)

// DefaultPipeSDDL keeps the daemon control pipe open to any LOCAL caller, on par
// with the Unix socket's 0666 mode.
//
//	D:P                 protected DACL, no inheritance
//	(D;;GA;;;NU)        deny GENERIC_ALL to NETWORK (remote/SMB)
//	(A;;GA;;;SY)        allow GENERIC_ALL to LocalSystem (the daemon itself)
//	(A;;GA;;;WD)        allow GENERIC_ALL to Everyone (local, per-RPC ACL gates)
func DefaultPipeSDDL() string {
	return "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;WD)"
}

// NewTransportCredentials returns gRPC transport credentials that derive the
// caller's identity from the named-pipe client token.
//
// This requires the client to dial at SECURITY_IDENTIFICATION (see dialNamedPipe).
func NewTransportCredentials() credentials.TransportCredentials {
	return winpipeCreds{}
}

type winpipeCreds struct{}

func (winpipeCreds) ClientHandshake(_ context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return conn, AuthInfo{}, nil
}

// ServerHandshake extracts the connecting client's identity from the pipe. Fails
// closed if the handle or token cannot be read.
func (winpipeCreds) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	// go-winio's pipe connection embeds *win32File, which exposes Fd().
	fdConn, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return nil, nil, fmt.Errorf("connection %T does not expose a pipe handle", conn)
	}
	handle := windows.Handle(fdConn.Fd())

	id, err := pipeClientIdentity(handle)
	if err != nil {
		return nil, nil, err
	}
	return conn, AuthInfo{
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.NoSecurity},
		Identity:       id,
	}, nil
}

func (winpipeCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "netbird-ipc-peercred"}
}

func (winpipeCreds) Clone() credentials.TransportCredentials { return winpipeCreds{} }

func (winpipeCreds) OverrideServerName(string) error { return nil }

// pipeClientIdentity reads the connecting client's user SID, enabled group SIDs,
// and elevation by impersonating the pipe client on this thread and reading the
// impersonation token.
func pipeClientIdentity(handle windows.Handle) (id Identity, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err = impersonateNamedPipeClient(handle); err != nil {
		return Identity{}, fmt.Errorf("impersonate named pipe client: %w", err)
	}
	defer func() {
		// Surface revert error if there are no other errors.
		revErr := windows.RevertToSelf()
		if err == nil {
			err = revErr
		}
	}()

	// openAsSelf=true: the token is opened using the daemon's process context
	// (LocalSystem), not the impersonated client's, so the open always succeeds.
	var token windows.Token
	if err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token); err != nil {
		return Identity{}, fmt.Errorf("open thread token: %w", err)
	}
	defer token.Close()

	tu, err := token.GetTokenUser()
	if err != nil {
		return Identity{}, fmt.Errorf("get token user: %w", err)
	}

	tg, err := token.GetTokenGroups()
	if err != nil {
		return Identity{}, fmt.Errorf("get token groups: %w", err)
	}
	var groups []string
	for _, g := range tg.AllGroups() {
		if g.Attributes&windows.SE_GROUP_ENABLED == 0 || g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0 {
			continue
		}
		groups = append(groups, g.Sid.String())
	}

	return Identity{
		SID:      tu.User.Sid.String(),
		Groups:   groups,
		Elevated: token.IsElevated(),
	}, nil
}

func impersonateNamedPipeClient(h windows.Handle) error {
	r, _, e := procImpersonateNamedPipeClient.Call(uintptr(h))
	if r == 0 {
		return e
	}
	return nil
}
