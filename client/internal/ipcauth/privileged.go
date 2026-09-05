package ipcauth

import (
	"os"
	"runtime"
)

// Fields of the ErrorInfo detail the daemon attaches to a PermissionDenied it
// raises for an operation that requires root/administrator. Clients match on
// Reason and Domain rather than on the message text, and render the summary and
// command themselves so the user gets guidance instead of a gRPC error dump.
const (
	// ErrorReasonPrivilegeRequired identifies the detail.
	ErrorReasonPrivilegeRequired = "PRIVILEGE_REQUIRED"
	// ErrorDomain scopes the reason to the NetBird daemon.
	ErrorDomain = "daemon.netbird.io"
	// ErrorMetaSummary is the one-sentence explanation of what was refused.
	ErrorMetaSummary = "summary"
	// ErrorMetaCommand is the command that performs the same operation with the
	// privileges it needs, ready to copy and run.
	ErrorMetaCommand = "command"
)

// The identity of the process evaluating callers, captured once because it cannot
// change. selfKnown is false when it could not be read, in which case nothing is
// ever treated as this process. selfMayDelegate additionally requires this
// process to be unprivileged: see IsPrivilegedCaller.
var (
	selfIdentity    Identity
	selfKnown       bool
	selfMayDelegate bool
	// selfPID is this process's PID, used to recognise the daemon dialling itself.
	selfPID = os.Getpid()
)

func init() {
	id, err := CurrentProcessIdentity()
	if err != nil {
		return
	}
	selfIdentity, selfKnown = id, true
	// Only an unprivileged daemon delegates its authority to its own identity.
	// When it is root or LocalSystem, sharing its identity does not mean sharing
	// its power: on Windows a filtered and a full token carry the same SID, so
	// matching there would let a non-elevated shell of an administrator account
	// act as an administrator, which is the boundary the token check exists to
	// keep.
	selfMayDelegate = !id.IsPrivileged()
}

// IsDaemonSelf reports whether an identity is this very process. The JSON gateway
// runs inside the daemon and re-dials it locally, so this is what distinguishes
// the gateway from any other caller, whatever user the daemon runs as.
func IsDaemonSelf(id Identity) bool {
	if !selfKnown || id.IsWindows() != selfIdentity.IsWindows() {
		return false
	}
	if id.IsWindows() {
		return id.SID != "" && id.SID == selfIdentity.SID
	}
	return id.UID == selfIdentity.UID
}

// IsPrivilegedCaller reports whether an identity may make the changes the daemon
// restricts to the platform administrator. This is the daemon's own rule and
// cannot be evaluated by a client, which does not know what the daemon runs as.
//
// Beyond root/administrator it accepts a caller running as the daemon's own
// identity when the daemon is itself unprivileged. That keeps a rootless container
// working, where there is no uid 0 at all, and a Windows daemon in netstack mode,
// which needs no administrator rights. In those setups a caller sharing the
// daemon's identity can already rewrite the config files it reads and replace the
// binary it runs, so refusing it a config change would protect nothing; and an
// unprivileged daemon cannot hand out a root shell in the first place.
func IsPrivilegedCaller(id Identity) bool {
	if id.IsPrivileged() {
		return true
	}
	return selfMayDelegate && IsDaemonSelf(id)
}

// SelfDelegatesTo returns the identity this process delegates its authority to,
// and whether it delegates at all. Only an unprivileged daemon does: see
// IsPrivilegedCaller. It exists so a refusal can name who may actually perform the
// operation, because on such a host root is neither required nor necessarily
// available.
func SelfDelegatesTo() (Identity, bool) {
	if !selfKnown || !selfMayDelegate {
		return Identity{}, false
	}
	return selfIdentity, true
}

// The values PrivilegedActorKey returns.
const (
	ActorKeyAdministrator = "administrator"
	ActorKeyRoot          = "root"
)

// PrivilegedActor names the principal a privileged operation requires, for use
// in messages shown to the user.
func PrivilegedActor() string {
	if runtime.GOOS == "windows" {
		return "administrator privileges"
	}
	return "root"
}

// PrivilegedActorKey identifies that principal without wording it, for a client
// that writes its own message in the user's language. The words PrivilegedActor
// returns are English, and a translated sentence cannot borrow them.
func PrivilegedActorKey() string {
	if runtime.GOOS == "windows" {
		return ActorKeyAdministrator
	}
	return ActorKeyRoot
}

// ElevatedCommand renders a command so that running it grants the privileges the
// operation needs. Windows has no in-line equivalent of sudo, so the command is
// returned unchanged and the user is expected to run it from an elevated
// terminal.
func ElevatedCommand(command string) string {
	if runtime.GOOS == "windows" {
		return command
	}
	return "sudo " + command
}

// UpCommand renders an elevated `netbird up` with the given flags, preceded by a
// `down`. The down is what makes the command work on a connected client: `netbird
// up` prints "Already connected" and returns without applying any config flag, so
// on its own the command would appear to do nothing. It is a no-op, exit 0, when
// the client is not connected.
//
// ";" rather than "&&" so the line can be pasted into any of the shells a user
// might have: PowerShell 5.1, still the default on Windows Server, rejects "&&"
// as a syntax error.
func UpCommand(flags string) string {
	return ElevatedCommand("netbird down") + "; " + ElevatedCommand("netbird up "+flags)
}
