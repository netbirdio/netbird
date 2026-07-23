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
	procRevertToSelf               = modadvapi32.NewProc("RevertToSelf")
)

// Windows group-SID attribute flags (winnt.h): a group only counts toward
// membership when it is enabled and not marked use-for-deny-only.
const (
	seGroupEnabled        = 0x00000004
	seGroupUseForDenyOnly = 0x00000010
)

// DefaultPipeSDDL restricts the daemon control pipe to LocalSystem (SY), the
// Administrators group (BA), and interactive logon users (IU). It deliberately
// excludes Authenticated Users / Everyone so remote or arbitrary service
// principals cannot connect. This is the connection gate; the interceptor still
// does per-RPC authorization by caller identity.
func DefaultPipeSDDL() string {
	return "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)"
}

// NewTransportCredentials returns gRPC transport credentials that derive the
// caller's identity from the named-pipe client token, following Microsoft's
// "Verifying Client Access with ACLs" pattern: ImpersonateNamedPipeClient ->
// OpenThreadToken -> RevertToSelf. Per threat-model M-NOIMP, impersonation is
// used only to read the client token for identity, never to perform privileged work.
func NewTransportCredentials() credentials.TransportCredentials {
	return winpipeCreds{}
}

type winpipeCreds struct{}

func (winpipeCreds) ClientHandshake(_ context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return conn, AuthInfo{}, nil
}

// ServerHandshake extracts the connecting client's identity from the pipe token.
// Fails closed if the handle or token cannot be read.
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
// and elevation from the named-pipe handle. The impersonation window is kept as
// small as possible and pinned to the OS thread (impersonation is thread-local).
func pipeClientIdentity(handle windows.Handle) (Identity, error) {
	var pid uint32
	hasPID := windows.GetNamedPipeClientProcessId(handle, &pid) == nil

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := impersonateNamedPipeClient(handle); err != nil {
		return Identity{}, fmt.Errorf("impersonate named pipe client: %w", err)
	}
	defer func() { _ = revertToSelf() }()

	// openAsSelf=true: the token is opened using the daemon's process context
	// (LocalSystem), not the impersonated client's, so the open always succeeds.
	var token windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token); err != nil {
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
		if g.Attributes&seGroupEnabled == 0 || g.Attributes&seGroupUseForDenyOnly != 0 {
			continue
		}
		groups = append(groups, g.Sid.String())
	}

	return Identity{
		SID:      tu.User.Sid.String(),
		Groups:   groups,
		Elevated: token.IsElevated(),
		PID:      int32(pid),
		HasPID:   hasPID,
	}, nil
}

func impersonateNamedPipeClient(h windows.Handle) error {
	r, _, e := procImpersonateNamedPipeClient.Call(uintptr(h))
	if r == 0 {
		return e
	}
	return nil
}

func revertToSelf() error {
	r, _, e := procRevertToSelf.Call()
	if r == 0 {
		return e
	}
	return nil
}
