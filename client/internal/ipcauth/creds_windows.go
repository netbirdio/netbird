//go:build windows

package ipcauth

import (
	"context"
	"fmt"
	"net"
	"runtime"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"google.golang.org/grpc/credentials"
)

var (
	modadvapi32                    = windows.NewLazySystemDLL("advapi32.dll")
	procImpersonateNamedPipeClient = modadvapi32.NewProc("ImpersonateNamedPipeClient")
)

// DefaultPipeSDDL is the security descriptor for the daemon control pipe.
//
//	D:P          protected DACL, no inheritance
//	(A;;GA;;;SY) allow GENERIC_ALL to LocalSystem (the daemon's service account)
//	(A;;GA;;;WD) allow GENERIC_ALL to Everyone
//
// Any local caller may connect, as with a Unix socket at 0666; what a caller may
// actually do is decided from its token, not from the DACL. Remote callers are not
// a concern here: winio.ListenPipe creates the pipe with
// FILE_PIPE_REJECT_REMOTE_CLIENTS, so NPFS rejects connections from other machines
// before the descriptor is consulted.
//
// A deny ACE on the NETWORK SID would not add anything and would break callers:
// that SID is present in any network-logon token, which includes OpenSSH and WinRM
// sessions, so it denies administrators driving the CLI over SSH and denies the
// daemon itself when started from such a session.
func DefaultPipeSDDL() string {
	return "D:P(A;;GA;;;SY)(A;;GA;;;WD)"
}

// NewTransportCredentials returns gRPC transport credentials that derive the
// caller's identity from the named-pipe client token.
//
// The client must connect at SECURITY_IDENTIFICATION for the daemon to be able
// to read its token, which is what DialNamedPipe does.
func NewTransportCredentials() credentials.TransportCredentials {
	return winpipeCreds{}
}

// ConnIdentity extracts the caller's identity from an accepted named-pipe
// connection by impersonating the pipe client and reading its token. It is
// shared by the gRPC transport credentials and by the JSON gateway, which
// reads the identity of its own HTTP clients.
func ConnIdentity(conn net.Conn) (Identity, error) {
	// go-winio's pipe connection embeds *win32File, which exposes Fd().
	fdConn, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return Identity{}, fmt.Errorf("connection %T does not expose a pipe handle", conn)
	}
	return pipeClientIdentity(windows.Handle(fdConn.Fd()))
}

type winpipeCreds struct{}

func (winpipeCreds) ClientHandshake(_ context.Context, _ string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return conn, AuthInfo{}, nil
}

// ServerHandshake extracts the connecting client's identity and fails closed
// when the handle or token cannot be read, so a connection whose caller is
// unknown never reaches a handler.
func (winpipeCreds) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	id, err := ConnIdentity(conn)
	if err != nil {
		return nil, nil, err
	}
	return conn, AuthInfo{
		CommonAuthInfo: credentials.CommonAuthInfo{SecurityLevel: credentials.NoSecurity},
		Identity:       id,
	}, nil
}

func (winpipeCreds) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: AuthInfo{}.AuthType()}
}

func (winpipeCreds) Clone() credentials.TransportCredentials { return winpipeCreds{} }

func (winpipeCreds) OverrideServerName(string) error { return nil }

// pipeClientIdentity reads the connecting client's user SID, usable group
// SIDs, and elevation state by impersonating the pipe client on this thread
// and reading the resulting impersonation token.
func pipeClientIdentity(handle windows.Handle) (id Identity, err error) {
	// Impersonation is per-thread, so the goroutine must stay on this thread
	// until RevertToSelf, otherwise an unrelated goroutine could inherit the
	// impersonated context.
	runtime.LockOSThread()

	// The thread only goes back to the runtime's pool once it is provably no
	// longer impersonating the client. If the revert fails, leaving it locked
	// makes Go terminate it when this goroutine exits, which costs one thread
	// and keeps a thread running as the client from ever being reused.
	clean := false
	defer func() {
		if clean {
			runtime.UnlockOSThread()
		}
	}()

	if err = impersonateNamedPipeClient(handle); err != nil {
		clean = true
		return Identity{}, fmt.Errorf("impersonate named pipe client: %w", err)
	}
	defer func() {
		// Surface the revert failure only when nothing else failed: leaving
		// the thread impersonated is worse than the original error.
		revErr := windows.RevertToSelf()
		if revErr != nil {
			if err == nil {
				err = fmt.Errorf("revert impersonation: %w", revErr)
			}
			return
		}
		clean = true
	}()

	// openAsSelf=true opens the token with the daemon's own process context
	// rather than the impersonated client's, so the open cannot fail because
	// the client lacks access to its own token.
	var token windows.Token
	if err = windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token); err != nil {
		return Identity{}, fmt.Errorf("open thread token: %w", err)
	}
	defer func() {
		if cerr := token.Close(); cerr != nil {
			log.Debugf("close client token: %v", cerr)
		}
	}()

	return identityFromToken(token)
}

// identityFromToken reads the user SID, usable group SIDs and elevation state
// out of a Windows token.
func identityFromToken(token windows.Token) (Identity, error) {
	user, err := token.GetTokenUser()
	if err != nil {
		return Identity{}, fmt.Errorf("read token user: %w", err)
	}

	groups, err := tokenGroupSIDs(token)
	if err != nil {
		return Identity{}, err
	}

	return Identity{
		SID:      user.User.Sid.String(),
		Groups:   groups,
		Elevated: token.IsElevated(),
	}, nil
}

// tokenGroupSIDs returns the SIDs of the groups the token can actually
// exercise. Groups that are disabled or marked deny-only are skipped: a
// UAC-filtered administrator carries BUILTIN\Administrators as deny-only, and
// treating that as membership would hand every admin account privilege it
// cannot currently use.
func tokenGroupSIDs(token windows.Token) ([]string, error) {
	tg, err := token.GetTokenGroups()
	if err != nil {
		return nil, fmt.Errorf("read token groups: %w", err)
	}

	var sids []string
	for _, g := range tg.AllGroups() {
		if g.Attributes&windows.SE_GROUP_ENABLED == 0 {
			continue
		}
		if g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0 {
			continue
		}
		sids = append(sids, g.Sid.String())
	}
	return sids, nil
}

func impersonateNamedPipeClient(h windows.Handle) error {
	r, _, e := procImpersonateNamedPipeClient.Call(uintptr(h))
	if r == 0 {
		return e
	}
	return nil
}
