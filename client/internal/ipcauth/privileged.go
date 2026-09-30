package ipcauth

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

	// ErrorReasonSessionHeld identifies a refusal caused by another user's live
	// connection.
	ErrorReasonSessionHeld = "SESSION_HELD"

	// ErrorReasonNotProfileOwner identifies a refusal caused by the profile
	// belonging to another account. It carries no command either: privilege is
	// not what the method asked for, so telling the caller to elevate would send
	// them the wrong way.
	ErrorReasonNotProfileOwner = "NOT_PROFILE_OWNER"

	// ErrorReasonProfileUnowned identifies a refusal caused by the profile
	// recording no owner. It carries the command that records one.
	ErrorReasonProfileUnowned = "PROFILE_UNOWNED"
)

// The identity of the process evaluating callers, captured once because it cannot
// change. It stays the zero Identity when it could not be read, and the zero
// Identity is not Known, so nothing is ever treated as this process.
// selfMayDelegate additionally requires this process to be unprivileged: see
// IsPrivilegedCaller.
var (
	selfIdentity    Identity
	selfMayDelegate bool
	// selfPID is this process's PID, used to recognise the daemon dialling itself.
	selfPID = os.Getpid()
)

func init() {
	id, err := CurrentProcessIdentity()
	if err != nil {
		return
	}
	selfIdentity = id
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
	// An identity the kernel did not vouch for is nobody, least of all us: the
	// zero Identity carries uid 0, which would otherwise match a root daemon.
	if !id.Known() || !selfIdentity.Known() {
		return false
	}
	if id.IsWindows() != selfIdentity.IsWindows() {
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
	if !selfIdentity.Known() || !selfMayDelegate {
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

// Denial is a refusal the daemon explained, read back off the error it raised.
// The reason identifies which refusal it was, so a consumer can present each one
// in its own way without matching on message text.
type Denial struct {
	Reason  string
	Summary string
	Command string
}

// DenialFrom returns the refusal a daemon error explains, if it explains one.
func DenialFrom(err error) (Denial, bool) {
	if err == nil {
		return Denial{}, false
	}

	st := status.Convert(err)
	for _, detail := range st.Details() {
		info, ok := detail.(*errdetails.ErrorInfo)
		if !ok || info.GetDomain() != ErrorDomain {
			continue
		}

		summary := info.GetMetadata()[ErrorMetaSummary]
		if summary == "" {
			// A detail with no summary still refused something. The status
			// message carries the same sentence, and showing it beats showing
			// a consumer nothing.
			summary = strings.TrimSpace(st.Message())
		}

		return Denial{
			Reason:  info.GetReason(),
			Summary: summary,
			Command: info.GetMetadata()[ErrorMetaCommand],
		}, true
	}

	return Denial{}, false
}

// PrivilegeError builds the PermissionDenied carrying summary and command.
func PrivilegeError(summary, command string) error {
	return denialError(ErrorReasonPrivilegeRequired, summary, command)
}

// SessionHeldError refuses an operation because another user has the machine
// connected.
func SessionHeldError(action string) error {
	actor, command := RequiredActor(DownCommand())
	return denialError(ErrorReasonSessionHeld, sessionHeldSummary(action)+remedyNote(actor, command), command)
}

// NotOwnerError refuses an operation because the profile it addresses belongs to
// somebody else.
func NotOwnerError(action string) error {
	return denialError(ErrorReasonNotProfileOwner, notOwnerSummary(action), "")
}

// UnownedError refuses an operation because the profile it addresses has no
// owner on record, and names the command that gives it one. atConsole is whether
// the caller sits at one of this machine's consoles.
func UnownedError(action, handle string, atConsole bool) error {
	actor, command := RequiredActor(ClaimCommand(handle))
	return denialError(ErrorReasonProfileUnowned, unownedSummary(action, atConsole)+remedyNote(actor, command), command)
}

// remedyNote names who has to run the command a refusal offers.
func remedyNote(actor, command string) string {
	if strings.HasPrefix(command, "sudo ") {
		return ""
	}
	return " Running this requires " + actor + "."
}

// DownCommand renders the elevated command that ends the live session.
func DownCommand() string {
	return ElevatedCommand("netbird down")
}

// ClaimCommand renders the elevated command that records an owner for a profile.
// With no profile to name it keeps the placeholder for the caller to fill in.
func ClaimCommand(handle string) string {
	if handle == "" {
		handle = "<profile>"
	}
	return ElevatedCommand("netbird profile claim " + handle)
}

// sessionHeldSummary says whose the connection is and why that settles it.
func sessionHeldSummary(action string) string {
	return refusedSubject(action) + " refused while another user has this machine connected. " +
		"The active profile and the connection on it belong to the user who brought it up, " +
		"so the connection has to come down before anyone else can use the machine."
}

// notOwnerSummary says who the profile belongs to and why that settles it.
func notOwnerSummary(action string) string {
	return refusedSubject(action) + " refused because the profile it addresses belongs to another user. " +
		"A profile and the configuration on it stay with the account that created or claimed it, " +
		"so use one of your own or ask an administrator to hand this one over."
}

// unownedSummary says the profile belongs to nobody yet and what changes that.
// Only a caller away from the console is told about it, since a profile left
// unclaimed while somebody is at one got that way for another reason.
func unownedSummary(action string, atConsole bool) string {
	cause := ""
	if !atConsole {
		cause = "A profile is claimed by the user who sets it up at this machine's console (in front of the machine), " +
			"and nobody has done that here. "
	}
	return refusedSubject(action) + " refused because the profile it addresses has no owner on record. " +
		cause + "An explicit claim of the profile is needed."
}

// refusedSubject opens a refusal with what was refused, falling back to the
// command itself for a method that names no action.
func refusedSubject(action string) string {
	if action == "" {
		return "This command is"
	}
	return capitalize(action) + " is"
}

// denialError builds a PermissionDenied carrying a summary a client can render,
// and a command when there is one to give.
func denialError(reason, summary, command string) error {
	message := summary
	metadata := map[string]string{ErrorMetaSummary: summary}
	if command != "" {
		message = fmt.Sprintf("%s\n\n%s", summary, command)
		metadata[ErrorMetaCommand] = command
	}

	st := status.New(codes.PermissionDenied, message)
	detailed, err := st.WithDetails(&errdetails.ErrorInfo{
		Reason:   reason,
		Domain:   ErrorDomain,
		Metadata: metadata,
	})
	if err != nil {
		log.Debugf("attach %s error detail: %v", reason, err)
		return st.Err()
	}
	return detailed.Err()
}

// RequiredActor names who may perform the operation and adjusts the command to
// match.
func RequiredActor(command string) (string, string) {
	self, delegates := SelfDelegatesTo()
	if !delegates {
		return PrivilegedActor(), command
	}
	return fmt.Sprintf("the user the daemon runs as (%s)", self), strings.ReplaceAll(command, "sudo ", "")
}

// PrivilegeSummary states what is refused and what it needs, in one sentence
// that reads the same in a dialog and in a terminal.
func PrivilegeSummary(action, actor string) string {
	return fmt.Sprintf("%s requires %s.", capitalize(action), actor)
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
