package daemonaddr

import (
	"context"
	"net"
	"runtime"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	// WindowsPipeAddr is the default daemon address on Windows. A named pipe
	// carries the connecting process's token, which loopback TCP does not, so
	// it is the only Windows transport on which the daemon can tell who is
	// calling it.
	WindowsPipeAddr = "npipe://netbird"

	// legacyWindowsAddr is the loopback-TCP address the Windows daemon used
	// before named-pipe support.
	legacyWindowsAddr = "tcp://127.0.0.1:41731"

	pipeScheme = "npipe://"

	// protectedPrefix is the NPFS namespace in which only LocalSystem and
	// members of BUILTIN\Administrators may create a pipe. A daemon running as
	// the service account creates its pipe there so that an unprivileged process
	// cannot pre-create the name, which would keep the daemon from starting and
	// leave callers talking to the squatter. Opening such a pipe needs no
	// privilege, so unprivileged clients still reach the daemon.
	protectedPrefix = `ProtectedPrefix\Administrators\`
)

// DialTarget returns the gRPC dial target and transport options for a daemon
// address. The npipe scheme needs a context dialer because gRPC has no
// named-pipe resolver; unix and tcp are handled by gRPC itself.
func DialTarget(addr string) (string, []grpc.DialOption) {
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}

	if name, ok := strings.CutPrefix(addr, pipeScheme); ok {
		paths := PipePaths(name)
		opts = append(opts, grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return dialPipePaths(ctx, paths)
		}))
		return "passthrough:///netbird-daemon-pipe", opts
	}

	return strings.TrimPrefix(addr, "tcp://"), opts
}

// PipePath maps an npipe address name ("netbird", from "npipe://netbird") to a
// Windows named-pipe path (\\.\pipe\netbird). A fully qualified path is left as
// is.
func PipePath(name string) string {
	if strings.HasPrefix(name, `\\`) {
		return name
	}
	return `\\.\pipe\` + name
}

// PipePaths returns the paths a daemon control pipe may live at for an npipe
// address name, in the order both sides must try them: the protected name first,
// then the plain one.
//
// The daemon serves the first it can create, which is the protected name when it
// runs as the service account and the plain one when it runs as an ordinary user,
// as it does in netstack mode. Clients therefore have to try both, and because a
// client cannot tell from the name alone who created the pipe, the plain name is
// only usable once the server's identity has been checked: see
// verifyPipeServer.
//
// A fully qualified path is what the operator asked for and is used as is.
func PipePaths(name string) []string {
	if strings.HasPrefix(name, `\\`) {
		return []string{name}
	}
	return []string{PipePath(protectedPrefix + name), PipePath(name)}
}

// IsProtectedPipePath reports whether a pipe path is in the namespace only an
// administrator or LocalSystem can create in, which is what lets a client trust
// such a pipe from its name alone.
func IsProtectedPipePath(path string) bool {
	return strings.HasPrefix(path, `\\.\pipe\`+protectedPrefix)
}

// MigrateLegacy upgrades the pre-named-pipe Windows daemon address to the named
// pipe, reporting whether it rewrote the address. Existing installs persist the
// daemon address, so without this an upgraded daemon would keep listening on
// loopback TCP, where callers carry no identity and privileged operations would
// have to be refused for everyone. Only the exact legacy default is rewritten:
// a deliberately chosen custom address is left alone.
func MigrateLegacy(addr string) (string, bool) {
	return migrateLegacyForOS(runtime.GOOS, addr)
}

func migrateLegacyForOS(goos, addr string) (string, bool) {
	if goos == "windows" && addr == legacyWindowsAddr {
		return WindowsPipeAddr, true
	}
	return addr, false
}
