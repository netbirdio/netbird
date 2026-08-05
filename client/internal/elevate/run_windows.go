package elevate

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

const (
	// seeMaskNoCloseProcess keeps the started process's handle open in
	// hProcess so we can wait for it.
	seeMaskNoCloseProcess = 0x00000040
	// seeMaskNoAsync makes ShellExecuteExW finish its work before returning,
	// which it must when the calling thread does not pump messages.
	seeMaskNoAsync = 0x00000100
	// seeMaskFlagNoUI suppresses the shell's own error dialogs; the UAC consent
	// dialog is not one of them and still appears.
	seeMaskFlagNoUI = 0x00000400

	// swHide: the one-shot has no window to show.
	swHide = 0

	// sFalse (S_FALSE) answers CoInitializeEx when COM is already up on this
	// thread in the mode we asked for; rpcChangedMode (RPC_E_CHANGED_MODE) when
	// it is up in the other one.
	sFalse         = 1
	rpcChangedMode = 0x80010106
)

// shellExecuteInfoW mirrors SHELLEXECUTEINFOW. The field order and Go's own
// padding match the C layout on both 386 and amd64.
type shellExecuteInfoW struct {
	cbSize         uint32
	fMask          uint32
	hwnd           windows.HWND
	lpVerb         *uint16
	lpFile         *uint16
	lpParameters   *uint16
	lpDirectory    *uint16
	nShow          int32
	hInstApp       windows.Handle
	lpIDList       uintptr
	lpClass        *uint16
	hkeyClass      windows.Handle
	dwHotKey       uint32
	hIconOrMonitor windows.Handle
	hProcess       windows.Handle
}

var (
	shell32            = windows.NewLazySystemDLL("shell32.dll")
	procShellExecuteEx = shell32.NewProc("ShellExecuteExW")
)

// run starts self elevated with the "runas" verb, which is what raises the UAC
// consent dialog, and waits for it to finish. Windows decides whether consent is
// enough or an administrator's credentials are needed, and collects them itself.
func run(ctx context.Context, self string, args []string) error {
	verb, err := windows.UTF16PtrFromString("runas")
	if err != nil {
		return fmt.Errorf("encode verb: %w", err)
	}
	file, err := windows.UTF16PtrFromString(self)
	if err != nil {
		return fmt.Errorf("encode %s: %w", self, err)
	}
	params, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(args))
	if err != nil {
		return fmt.Errorf("encode arguments: %w", err)
	}

	info := shellExecuteInfoW{
		fMask:        seeMaskNoCloseProcess | seeMaskNoAsync | seeMaskFlagNoUI,
		hwnd:         ownerWindow(),
		lpVerb:       verb,
		lpFile:       file,
		lpParameters: params,
		nShow:        swHide,
	}
	info.cbSize = uint32(unsafe.Sizeof(info))

	process, err := shellExecute(&info)
	if err != nil {
		return err
	}
	defer func() {
		if err := windows.CloseHandle(process); err != nil {
			log.Debugf("close elevated process handle: %v", err)
		}
	}()

	return waitForProcess(ctx, process)
}

// shellExecute performs the call itself. ShellExecuteExW wants COM initialised on
// the calling thread, so the goroutine is pinned to one for the duration and COM
// is set up on it; an "already initialised, different mode" answer is fine,
// because then somebody else has done it for us.
func shellExecute(info *shellExecuteInfoW) (windows.Handle, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	switch err := windows.CoInitializeEx(0, windows.COINIT_APARTMENTTHREADED); {
	case err == nil, isHResult(err, sFalse):
		// Ours, or already initialised in the same mode: either way this call
		// counts and has to be balanced.
		defer windows.CoUninitialize()
	case isHResult(err, rpcChangedMode):
		// The thread is already in the other apartment model. ShellExecuteExW
		// works there too, and there is nothing of ours to balance.
	default:
		return 0, fmt.Errorf("initialise COM: %w", err)
	}

	ret, _, lastErr := procShellExecuteEx.Call(uintptr(unsafe.Pointer(info)))
	if ret != 0 {
		return info.hProcess, nil
	}

	if errors.Is(lastErr, windows.ERROR_CANCELLED) {
		return 0, ErrDeclined
	}
	return 0, fmt.Errorf("run elevated: %w", lastErr)
}

// ownerWindow returns this process's foreground window, and 0 when the window in
// front belongs to somebody else or cannot be attributed. ShellExecuteExW takes it
// as the parent for the UI it raises, which is what keeps the consent dialog in
// front of the window the user was just clicking in instead of behind it. It is
// also what a remote-desktop session needs to place the dialog at all when the
// secure desktop is switched off.
func ownerWindow() windows.HWND {
	hwnd := windows.GetForegroundWindow()
	if hwnd == 0 {
		return 0
	}

	var pid uint32
	if _, err := windows.GetWindowThreadProcessId(hwnd, &pid); err != nil {
		log.Debugf("cannot attribute the foreground window, raising the prompt without an owner: %v", err)
		return 0
	}
	if pid != windows.GetCurrentProcessId() {
		return 0
	}
	return hwnd
}

// isHResult reports whether err carries the given HRESULT. CoInitializeEx
// returns its HRESULT as an Errno, so the comparison is on the raw value.
func isHResult(err error, hresult uintptr) bool {
	var errno windows.Errno
	return errors.As(err, &errno) && uintptr(errno) == hresult
}

func waitForProcess(ctx context.Context, process windows.Handle) error {
	// The wait is interruptible so a cancelled context stops us waiting on a
	// consent dialog nobody is going to answer. The elevated process is not
	// ours to kill, and it either applies the change or does not.
	for {
		event, err := windows.WaitForSingleObject(process, 250)
		if err != nil {
			return fmt.Errorf("wait for the elevated process: %w", err)
		}
		if event == uint32(windows.WAIT_OBJECT_0) {
			break
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}

	var code uint32
	if err := windows.GetExitCodeProcess(process, &code); err != nil {
		return fmt.Errorf("read the elevated process's exit code: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("elevated netbird exited with %d", code)
	}
	return nil
}

// mechanismAvailable is true on Windows: UAC prompts for consent when the user
// is an administrator and for an administrator's credentials when they are not,
// so there is always something to ask.
func mechanismAvailable() bool {
	return true
}
