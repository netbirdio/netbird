package elevate

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"github.com/ebitengine/purego"
	log "github.com/sirupsen/logrus"
)

// Authorization Services, reached through purego rather than cgo so the released
// binaries keep building with CGO_ENABLED=0.
//
// The prompt belongs to this process, which is what makes it carry the
// application's name and our own explanation. Going through osascript instead puts
// the very same trampoline behind a dialog attributed to osascript, and means
// handing a shell a command line to re-parse.
//
// # On AuthorizationExecuteWithPrivileges
//
// It is deprecated, and Apple's guidance (Quinn, "BSD Privilege Escalation on
// macOS", developer.apple.com/forums/thread/708765) is "while it still works, it's
// been deprecated for many years. Do not use it in a widely distributed product."
// It is used here anyway, knowingly, because the alternatives Apple offers are for
// *obtaining* ongoing privileges — an installer package, SMAppService, SMJobBless —
// and NetBird already has what they would install: a launchd daemon running as
// root. What is missing is only a way for an unprivileged client to ask it to act.
//
// The way to that without a deprecated call is to authorize the client instead of
// elevating one: the app takes the right with AuthorizationCreate, passes the
// AuthorizationExternalForm to the daemon, and the daemon checks it with
// AuthorizationCopyRights before acting — none of which is deprecated. It is the
// better design and it is where this should end up. It also means the daemon
// accepting an authorization over its control socket, which is a new way to be
// asked for privileged work and wants reviewing as such, so it is deliberately not
// bundled in with the rest of this.
//
// Until then, three things keep the deprecation from being a trap. Every symbol is
// resolved with an error rather than a panic, so a macOS that has dropped this
// function leaves the app offering the user a command instead of crashing on the
// way to a prompt. A failure to run the tool is reported as ErrUnavailable, so the
// fallback is the same one an agent-less Linux session gets. And the whole path
// runs under guard, which turns a panic out of the FFI layer into that same
// fallback.
//
// One thing that is not optional: the elevated process must be signed with the
// hardened runtime, which is what stops DYLD_INSERT_LIBRARIES in the environment
// the trampoline passes on from loading somebody's library into a root process. The
// released app is signed and notarised, so it is; see also trustedSelf, which
// refuses to elevate an executable others can write.

const (
	securityFramework = "/System/Library/Frameworks/Security.framework/Security"
	libSystem         = "/usr/lib/libSystem.B.dylib"

	// trampoline is what the framework hands the tool to. Present on every macOS,
	// and worth confirming before offering a prompt rather than mid-prompt.
	trampoline = "/usr/libexec/security_authtrampoline"
)

// rightExecute is the right an administrator holds, and what
// AuthorizationExecuteWithPrivileges requires of us.
const rightExecute = "system.privilege.admin"

// promptKey is kAuthorizationEnvironmentPrompt, which puts a sentence of ours above
// the system's in the dialog. It is about the change rather than the mechanism.
const (
	promptKey  = "prompt"
	promptText = "NetBird needs to change a setting that grants SSH access to this computer."
)

// OSStatus values from SecBase.h that mean something to us; anything else is
// reported as it comes.
const (
	errAuthorizationSuccess               = 0
	errAuthorizationDenied                = -60005
	errAuthorizationCanceled              = -60006
	errAuthorizationInteractionNotAllowed = -60007
	errAuthorizationToolExecuteFailure    = -60031
	errAuthorizationToolEnvironmentError  = -60032
)

// AuthorizationFlags from Authorization.h.
const (
	flagDefaults           = 0
	flagInteractionAllowed = 1 << 0
	flagExtendRights       = 1 << 1
	flagDestroyRights      = 1 << 3
	flagPreAuthorize       = 1 << 4
)

// authorizationItem mirrors AuthorizationItem: a name, and a value the name gives
// meaning to. 32 bytes on both amd64 and arm64.
type authorizationItem struct {
	name        *byte
	valueLength uintptr
	value       unsafe.Pointer
	// flags is reserved by the API and always zero. Declared because the layout
	// is the contract: without it the struct is 24 bytes where C reads 32.
	flags uint32 //nolint:unused // part of the C layout
}

// authorizationItemSet mirrors AuthorizationItemSet, which serves as both an
// AuthorizationRights and an AuthorizationEnvironment.
type authorizationItemSet struct {
	count uint32
	items *authorizationItem
}

var (
	authorizationCreate                func(rights, environment *authorizationItemSet, flags uint32, authorization *uintptr) int32
	authorizationExecuteWithPrivileges func(authorization uintptr, pathToTool string, options uint32, arguments *uintptr, communicationsPipe *uintptr) int32
	authorizationFree                  func(authorization uintptr, flags uint32) int32
	fileno                             func(stream uintptr) int32
	fclose                             func(stream uintptr) int32

	loadOnce sync.Once
	loadErr  error
)

// load resolves the functions once. A framework that cannot be opened, or a symbol
// that is no longer there, leaves the host without a mechanism rather than taking
// the process down with it: see the note on deprecation above.
func load() error {
	loadOnce.Do(func() { loadErr = guard("loading Security.framework", resolve) })
	return loadErr
}

// guard turns a panic out of the FFI layer into an error, so an API that has
// changed under us costs the user a prompt rather than the window they were
// clicking in. purego panics on a signature it cannot map, and this is the one
// place in the client that calls a deprecated system function.
//
// It catches Go panics, which is what purego raises. A fault inside the framework
// itself is not a panic and not recoverable; the layout the tests pin down is what
// stands between us and that.
func guard(what string, fn func() error) (err error) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		log.Errorf("%s panicked: %v", what, r)
		err = fmt.Errorf("%w: %s: %v", ErrUnavailable, what, r)
	}()
	return fn()
}

func resolve() error {
	security, err := purego.Dlopen(securityFramework, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		return fmt.Errorf("open %s: %w", securityFramework, err)
	}
	system, err := purego.Dlopen(libSystem, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		return fmt.Errorf("open %s: %w", libSystem, err)
	}

	// purego.RegisterLibFunc panics on a symbol it cannot find, which is not how a
	// deprecated function's disappearance should reach the user.
	for _, fn := range []struct {
		ptr    any
		handle uintptr
		name   string
	}{
		{&authorizationCreate, security, "AuthorizationCreate"},
		{&authorizationExecuteWithPrivileges, security, "AuthorizationExecuteWithPrivileges"},
		{&authorizationFree, security, "AuthorizationFree"},
		{&fileno, system, "fileno"},
		{&fclose, system, "fclose"},
	} {
		symbol, err := purego.Dlsym(fn.handle, fn.name)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", fn.name, err)
		}
		if symbol == 0 {
			return fmt.Errorf("resolve %s: not present on this system", fn.name)
		}
		purego.RegisterFunc(fn.ptr, symbol)
	}
	return nil
}

// run asks the system to run self as root: first for the right, which is what puts
// up the authentication dialog and collects the password or takes the Touch ID,
// then for the tool. The credentials go to the system's authorization trampoline
// and never to us.
//
// The context bounds only our own waiting; the dialog belongs to the system and
// closes when the user answers it.
func run(ctx context.Context, self string, args []string) error {
	if err := load(); err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}

	return guard("asking for privileges", func() error {
		authorization, err := authorize()
		if err != nil {
			return err
		}
		defer authorizationFree(authorization, flagDestroyRights)

		return execute(ctx, authorization, self, args)
	})
}

func mechanismAvailable() bool {
	if err := load(); err != nil {
		return false
	}
	info, err := os.Stat(trampoline)
	return err == nil && !info.IsDir()
}

// authorize obtains the right, prompting for it. A dismissed dialog comes back as
// errAuthorizationCanceled and a password given up on as errAuthorizationDenied;
// both are the user's answer rather than a failure.
func authorize() (uintptr, error) {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	rights := itemSet(&pinner, authorizationItem{name: cString(&pinner, rightExecute)})
	environment := itemSet(&pinner, promptItem(&pinner))

	var authorization uintptr
	status := authorizationCreate(rights, environment,
		flagDefaults|flagInteractionAllowed|flagPreAuthorize|flagExtendRights, &authorization)

	switch status {
	case errAuthorizationSuccess:
		return authorization, nil
	case errAuthorizationCanceled, errAuthorizationDenied:
		return 0, ErrDeclined
	case errAuthorizationInteractionNotAllowed:
		// Nowhere to put a dialog, so there is nobody to ask: a launch daemon, or
		// a session with no window server.
		return 0, fmt.Errorf("%w: this session cannot show an authorization prompt", ErrUnavailable)
	default:
		return 0, fmt.Errorf("request %s: OSStatus %d", rightExecute, status)
	}
}

// execute runs the tool with the right in hand and waits for it by reading the pipe
// it is given until the tool closes it.
//
// AuthorizationExecuteWithPrivileges reports no exit status and does not say what
// process it started, which is why the one-shot says so itself: what it prints is
// the only evidence that the change was applied.
func execute(ctx context.Context, authorization uintptr, self string, args []string) error {
	var pinner runtime.Pinner
	defer pinner.Unpin()

	argv := make([]uintptr, 0, len(args)+1)
	for _, arg := range args {
		argv = append(argv, uintptr(unsafe.Pointer(cString(&pinner, arg))))
	}
	argv = append(argv, 0)
	pinner.Pin(&argv[0])

	var pipe uintptr
	status := authorizationExecuteWithPrivileges(authorization, self, flagDefaults, &argv[0], &pipe)
	switch status {
	case errAuthorizationSuccess:
	case errAuthorizationCanceled:
		return ErrDeclined
	case errAuthorizationToolExecuteFailure, errAuthorizationToolEnvironmentError:
		// The right was granted and the tool still did not start. Nothing the user
		// can do about it from here, so point them at the command instead.
		return fmt.Errorf("%w: the system would not run %s elevated (OSStatus %d)", ErrUnavailable, self, status)
	default:
		return fmt.Errorf("run %s elevated: OSStatus %d", self, status)
	}

	out, err := readPipe(ctx, pipe)
	if err != nil {
		return err
	}
	if !strings.Contains(out, AppliedMarker) {
		return fmt.Errorf("elevated netbird did not report the change as applied: %s", firstLine(out))
	}
	return nil
}

// readPipe drains the tool's output, which ends when the tool exits and is
// therefore also how we wait for it.
func readPipe(ctx context.Context, pipe uintptr) (string, error) {
	if pipe == 0 {
		return "", nil
	}
	defer fclose(pipe)

	fd := int(fileno(pipe))
	if fd < 0 {
		return "", nil
	}

	var out strings.Builder
	buf := make([]byte, 4096)
	for {
		if err := ctx.Err(); err != nil {
			return out.String(), err
		}
		n, err := syscall.Read(fd, buf)
		if n > 0 {
			out.Write(buf[:n])
		}
		if n <= 0 || err != nil {
			return out.String(), nil
		}
	}
}

// itemSet builds an AuthorizationItemSet over items, pinned for the call.
func itemSet(pinner *runtime.Pinner, items ...authorizationItem) *authorizationItemSet {
	pinner.Pin(&items[0])
	set := &authorizationItemSet{count: uint32(len(items)), items: &items[0]}
	pinner.Pin(set)
	return set
}

// promptItem is the environment entry carrying our sentence for the dialog.
func promptItem(pinner *runtime.Pinner) authorizationItem {
	value := []byte(promptText)
	pinner.Pin(&value[0])
	return authorizationItem{
		name:        cString(pinner, promptKey),
		valueLength: uintptr(len(value)),
		value:       unsafe.Pointer(&value[0]),
	}
}

// cString returns a NUL-terminated copy of s, pinned so the C side may hold it for
// the duration of the call.
func cString(pinner *runtime.Pinner, s string) *byte {
	b := append([]byte(s), 0)
	pinner.Pin(&b[0])
	return &b[0]
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "no output"
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
